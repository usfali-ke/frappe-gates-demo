"""Hermes AI security review as a G1 pipeline control (`ai-review` job).

    python3 .github/scripts/hermes_review.py

1. Forward: on pull_request events, send this run's PR event to the Hermes
   gateway, signed exactly like a GitHub webhook (X-Hub-Signature-256 HMAC
   over the body). The gateway is on the lab network, which is why the job
   runs on the self-hosted `lab-runner`. Review events (an approval) don't
   re-request a review — they reuse the one for the same head commit.
2. Wait: for Hermes's PR comment for THIS head commit — the one ending
   "Automated review by Hermes on commit <sha>", posted after this run asked
   (or, on review events, any time), by HERMES_COMMENTER when set.
3. Verdict: fail on any Critical/High finding in its table (the same bar as
   SAST and secrets); Medium/Low are advisory and reported in the detail.

Writes `result=<json>` ({status, detail, metrics}) to $GITHUB_OUTPUT like
verdict.py (and to $VERDICT_FILE when set), and exits 1 on fail, so a red
job is a failed control. Stdlib only. Source of truth:
security-dashboard/pipeline/github/hermes-pr-review/.

Env: HERMES_URL, HERMES_SECRET, GH_TOKEN, PR_NUMBER, HEAD_SHA,
GITHUB_REPOSITORY, GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_RUN_ID,
GITHUB_RUN_ATTEMPT; optional HERMES_COMMENTER, WAIT_SECONDS (default 1500),
VERDICT_FILE.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NoReturn

MARKER = re.compile(r"Automated review by Hermes on commit ([0-9a-f]{7,40})")
SEVERITY_ROW = re.compile(r"^\|\s*\**\s*(Critical|High|Medium|Low|Info)\b", re.I | re.M)
BLOCKING = {"critical", "high"}
POLL_SECONDS = 20

# The review is a PR comment with one markdown table row per finding. Those
# rows are also written as SARIF so DefectDojo can import them as a scanner
# (defectdojo-upload.yml) instead of the AI review living only in a comment.
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# security-severity is what DefectDojo's SARIF parser maps to its own severity,
# so Critical survives the trip (error/warning/note alone would collapse it).
SEVERITY_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
FILE_CELL = re.compile(r"([\w./-]+\.(?:py|js|ts|tsx|jsx|json|toml|yaml|yml|html|htm|sh|md|conf|ini|cfg))(?::(\d+))?")


def _http_url(url: str) -> str:
    """Only http(s): a file://, ftp:// or data: URL is never opened."""
    if urllib.parse.urlsplit(url).scheme.lower() not in ("https", "http"):
        raise ValueError(f"refusing non-HTTP(S) URL: {url!r}")
    return url


def _opener() -> urllib.request.OpenerDirector:
    opener = urllib.request.OpenerDirector()
    for h in (urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPDefaultErrorHandler(),
              urllib.request.HTTPErrorProcessor(), urllib.request.HTTPRedirectHandler(), urllib.request.UnknownHandler()):
        opener.add_handler(h)
    return opener


_HTTP = _opener()


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def finish(status: str, detail: str, **metrics) -> NoReturn:
    out = {"status": status, "detail": detail[:1000], "metrics": metrics}
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"result={json.dumps(out)}\n")
    if env("VERDICT_FILE"):
        os.makedirs(os.path.dirname(env("VERDICT_FILE")) or ".", exist_ok=True)
        with open(env("VERDICT_FILE"), "w") as f:
            json.dump({"control": "ai-review", **out}, f, indent=2)
    if env("GITHUB_STEP_SUMMARY"):
        with open(env("GITHUB_STEP_SUMMARY"), "a") as f:
            f.write(f"### AI security review (Hermes): {status}\n\n{detail}\n")
    print(f"{status}: {detail}")
    if status != "pass":
        print(f"::error::{detail[:500]}")
    sys.exit(0 if status == "pass" else 1)  # a verdict is final


DIFF_CAP = 60000  # characters; the prompt renders this into one message


def review_context(event: dict) -> dict:
    """The `{hermes_context.*}` block the route's prompt renders.

    The route prompt asks the reviewer to read an "AUTHENTICATED GITHUB PR
    CONTEXT" diff, but the lab gateway only substitutes keys it finds in the
    delivery payload — and a raw GitHub event has no diff. So the sender ships
    one: same repo, same PR, fetched here where the token and the checkout
    already exist. Without this the reviewer sees literal `{hermes_context...}`
    placeholders and answers "Security review: NOT COMPLETED", which is a green
    gate carrying no assurance.
    """
    pr = event.get("pull_request") or {}
    repo = (event.get("repository") or {}).get("full_name", "")
    number = event.get("number") or pr.get("number")
    diff, reason = "", ""
    if not (repo and number):
        reason = "the delivery carried no repository/number"
    else:
        # The REST API, not `gh`: the sender runs in whatever image the repo
        # pins, and a missing CLI must not silently turn into "no findings".
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/pulls/{number}",
            headers={
                "Accept": "application/vnd.github.v3.diff",
                "User-Agent": "hermes-review-sender",
                **({"Authorization": f"Bearer {token}"} if (token := env("GH_TOKEN") or env("GITHUB_TOKEN")) else {}),
            },
        )
        try:
            with _HTTP.open(req, timeout=180) as resp:
                diff = resp.read().decode("utf-8", "replace")
            if not diff.strip():
                reason = "the API returned an empty diff"
        except urllib.error.HTTPError as exc:
            reason = f"HTTP {exc.code} fetching the diff ({exc.reason})"[:200]
            diff = ""
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = f"{type(exc).__name__}: {exc}"[:200]
            diff = ""
    files = sorted({line.split(" b/", 1)[-1] for line in diff.splitlines() if line.startswith("diff --git ")})
    if len(diff) > DIFF_CAP:
        diff = diff[:DIFF_CAP] + f"\n\n[diff truncated at {DIFF_CAP} characters; {len(files)} files changed]\n"
    ctx = {
        "source": "pipeline (gh pr diff at the head commit)",
        "diff_status": "ok" if diff else "unavailable",
        "reason": reason or "n/a",
        "file_count": str(len(files)),
        "diff_bytes": str(len(diff.encode())),
        "changed_files": ", ".join(files)[:2000] or "none",
        "pr_diff": diff or "(the pipeline could not fetch the diff: " + (reason or "unknown") + ")",
    }
    print(f"context: {ctx['diff_status']} {ctx['diff_bytes']}b {ctx['file_count']} file(s)"
          + (f" — {reason}" if reason else ""))
    return ctx


def forward(body: bytes) -> str:
    secret = env("HERMES_SECRET")
    if not secret:
        finish("fail", "HERMES_WEBHOOK_SECRET is not set for this repository — the review can't be requested")
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    delivery = f"gha-{env('GITHUB_RUN_ID')}-{env('GITHUB_RUN_ATTEMPT', '1')}"
    req = urllib.request.Request(_http_url(env("HERMES_URL")), data=body, method="POST", headers={
        "Content-Type": "application/json", "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": sig,
    })
    try:
        with _HTTP.open(req, timeout=30) as resp:
            return f"HTTP {resp.status} {resp.read().decode()[:200]}"
    except urllib.error.HTTPError as exc:
        hint = {401: "signature rejected — HERMES_WEBHOOK_SECRET doesn't match the route secret",
                404: "no such route — check HERMES_WEBHOOK_URL", 429: "Hermes rate limit hit — re-run in a minute"}
        finish("fail", f"Hermes refused the review request: HTTP {exc.code} ({hint.get(exc.code, exc.reason)})")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        finish("fail", f"Hermes gateway unreachable at {env('HERMES_URL')}: {exc}")
    return ""


def comments(since: dt.datetime | None) -> list[dict]:
    repo, pr = env("GITHUB_REPOSITORY"), env("PR_NUMBER")
    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments?per_page=100"
    if since:
        url += "&since=" + urllib.parse.quote(since.strftime("%Y-%m-%dT%H:%M:%SZ"))
    out: list[dict] = []
    while url:
        req = urllib.request.Request(_http_url(url), headers={"Authorization": f"Bearer {env('GH_TOKEN')}", "Accept": "application/vnd.github+json"})
        with _HTTP.open(req, timeout=30) as resp:
            out.extend(json.loads(resp.read()))
            nxt = [p for p in resp.headers.get("Link", "").split(",") if 'rel="next"' in p]
            url = nxt[0].split(";")[0].strip(" <>") if nxt else ""
    return out


def findings_from(body: str) -> list[dict]:
    """One dict per markdown table row the reviewer wrote.

    Tolerant on purpose: the row layout belongs to the reviewer, so the file
    and the line are found by pattern, and the description is the longest
    remaining cell. A row with no file still becomes a finding, with the
    comment as its location.
    """
    out: list[dict] = []
    for line in body.splitlines():
        m = SEVERITY_ROW.match(line)
        if not m:
            continue
        cells = [c.strip().strip("*` ") for c in line.strip().strip("|").split("|")]
        severity = m.group(1).lower()
        file_name, start_line = None, 1
        for cell in cells:
            fm = FILE_CELL.search(cell)
            if fm:
                file_name, start_line = fm.group(1), int(fm.group(2) or 1)
                break
        description = max(
            (c for c in cells if c and c.lower() != severity and not FILE_CELL.search(c)),
            key=len,
            default="AI review finding",
        )
        out.append({"severity": severity, "file": file_name, "line": start_line, "message": description[:500]})
    return out


def write_sarif(body: str) -> int:
    """Write reports/ai-review/ai-review.sarif from the review's table rows."""
    rows = findings_from(body)
    rule_ids = {f"hermes-ai-review/{f['severity']}" for f in rows}
    rules = [
        {
            "id": rid,
            "name": rid.split("/")[-1],
            "shortDescription": {"text": f"AI security review: {rid.split('/')[-1]}"},
            "properties": {"security-severity": SEVERITY_SCORE[rid.split("/")[-1]]},
        }
        for rid in sorted(rule_ids)
    ]
    results = [
        {
            "ruleId": f"hermes-ai-review/{f['severity']}",
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"] or "."},
                        "region": {"startLine": max(1, f["line"])},
                    }
                }
            ],
            "properties": {"security-severity": SEVERITY_SCORE[f["severity"]]},
        }
        for f in rows
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Hermes AI security review",
                        "informationUri": "https://github.com/NousResearch/hermes",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    out_dir = env("OUT") or "reports/ai-review"
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "ai-review.sarif")
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
    print(f"wrote {path} ({len(results)} finding(s))")
    return len(results)


def review_for(head: str, asked_at: dt.datetime | None) -> dict | None:
    commenter = env("HERMES_COMMENTER")
    for c in reversed(comments(asked_at)):  # newest first
        m = MARKER.search(c.get("body") or "")
        if not m or not head.startswith(m.group(1)) and not m.group(1).startswith(head):
            continue
        if commenter and (c.get("user") or {}).get("login") != commenter:
            continue
        created = dt.datetime.fromisoformat(c["created_at"].replace("Z", "+00:00"))
        if asked_at and created < asked_at:
            continue
        return c
    return None


def verdict(comment: dict) -> None:
    body = comment.get("body") or ""
    first = body.strip().splitlines()[0] if body.strip() else ""
    counts: dict[str, int] = {}
    for sev in SEVERITY_ROW.findall(body):
        counts[sev.lower()] = counts.get(sev.lower(), 0) + 1
    blocking = sum(n for s, n in counts.items() if s in BLOCKING)
    summary = ", ".join(f"{n} {s.title()}" for s, n in sorted(counts.items(), key=lambda kv: ["critical", "high", "medium", "low", "info"].index(kv[0]))) or "no findings"
    link = comment.get("html_url", "")
    try:
        write_sarif(body)
    except OSError as exc:  # never turn a landed review into a red gate
        print(f"::warning::could not write the SARIF report: {exc}")
    # "NOT COMPLETED" is the reviewer saying it could not look at the code.
    # A gate that passes on that carries no assurance, so it fails — the same
    # rule the rest of the dashboard follows: no evidence is not a pass.
    if first.lower().startswith("security review: not completed"):
        finish("fail", f"Hermes could not complete the review ({first}) — no assurance either way; see {link}", findings=0, blocking=0, verdict_line=first)
    if blocking:
        finish("fail", f"Hermes: {summary} — Critical/High block the merge; see {link}", findings=sum(counts.values()), blocking=blocking, verdict_line=first)
    finish("pass", f"Hermes: {first or 'review posted'} ({summary}; Medium/Low are advisory) — {link}", findings=sum(counts.values()), blocking=0, verdict_line=first)


def main() -> None:
    head = env("HEAD_SHA")
    event_name = env("GITHUB_EVENT_NAME")
    asked_at = None
    if event_name == "pull_request":
        with open(env("GITHUB_EVENT_PATH"), "rb") as f:
            event = json.load(f)
        if (event.get("pull_request") or {}).get("draft"):
            finish("fail", "draft PR — the AI review runs when the PR is marked ready for review")
        asked_at = dt.datetime.now(dt.UTC).replace(microsecond=0) - dt.timedelta(seconds=5)
        event["hermes_context"] = review_context(event)
        print("review requested:", forward(json.dumps(event, separators=(",", ":")).encode()))
    deadline = time.monotonic() + int(env("WAIT_SECONDS", "1500"))
    while True:
        try:
            found = review_for(head, asked_at)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"::warning::GitHub comments API: {exc}; retrying")
            found = None
        if found:
            verdict(found)
        if time.monotonic() > deadline:
            what = "for this head commit" if asked_at is None else "since this run requested it"
            finish("fail", f"no Hermes review {what} within {env('WAIT_SECONDS', '1500')}s (commit {head[:7]}) — check the gateway log")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
