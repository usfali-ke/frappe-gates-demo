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
