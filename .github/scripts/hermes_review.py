#!/usr/bin/env python3

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
from pathlib import Path



# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HERMES_URL = os.environ["HERMES_URL"]
HERMES_SECRET = os.environ["HERMES_SECRET"]

GH_TOKEN = os.environ["GH_TOKEN"]

REPOSITORY = os.environ.get("REPOSITORY") or os.environ.get(
    "GITHUB_REPOSITORY", ""
)

PR_NUMBER = os.environ.get("PR_NUMBER", "")
HEAD_SHA = os.environ.get("HEAD_SHA", "")

HERMES_COMMENTER = os.environ.get("HERMES_COMMENTER", "").strip()

WAIT_SECONDS = int(os.environ.get("WAIT_SECONDS", "1500"))
MAX_DIFF_BYTES = int(os.environ.get("MAX_DIFF_BYTES", "450000"))

GITHUB_EVENT_PATH = os.environ["GITHUB_EVENT_PATH"]
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT")

OUT = Path(os.environ.get("OUT", "reports/ai-review"))
VERDICT_FILE = Path(
    os.environ.get(
        "VERDICT_FILE",
        str(OUT / "verdict.json"),
    )
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    print(f"[hermes-review] {message}", flush=True)


def _http_url(url: str) -> str:
    """Only http(s) URLs are ever opened: a file:, ftp: or data: URL is refused
    before it reaches urllib (the dynamic-urllib-use-detected concern)."""
    if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
        raise RuntimeError(f"refusing non-HTTP(S) URL: {url!r}")
    return url


def run_gh(*args: str, timeout: int = 120) -> str:
    """
    Read-only GitHub access using the workflow's GITHUB_TOKEN over the REST
    API (stdlib only). The self-hosted lab-runner has no `gh` binary, so this
    implements the three invocations this script needs, with `gh`'s argument
    shapes:

      pr diff <n> --repo <owner/repo>               -> unified diff
      pr diff <n> --repo <owner/repo> --name-only   -> changed file names
      api <path>                                    -> raw JSON body
    """

    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    accept = "application/vnd.github+json"

    if args[:2] == ("pr", "diff"):
        number, repo = args[2], args[args.index("--repo") + 1]
        if "--name-only" in args:
            names: list[str] = []
            page = 1
            while True:
                chunk = json.loads(_gh_http(
                    f"{api}/repos/{repo}/pulls/{number}/files?per_page=100&page={page}",
                    accept, timeout))
                names.extend(f["filename"] for f in chunk)
                if len(chunk) < 100 or page >= 30:
                    break
                page += 1
            return "\n".join(names) + ("\n" if names else "")
        return _gh_http(f"{api}/repos/{repo}/pulls/{number}",
                        "application/vnd.github.diff", timeout)

    if args[:1] == ("api",) and len(args) == 2:
        return _gh_http(f"{api}/{args[1].lstrip('/')}", accept, timeout)

    raise RuntimeError(f"unsupported GitHub request: {' '.join(args)}")


def _gh_http(url: str, accept: str, timeout: int) -> str:
    request = urllib.request.Request(_http_url(url), headers={
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hermes-review",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosemgrep: dynamic-urllib-use-detected -- scheme checked by _http_url
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"GitHub API {exc.code} for {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub API unreachable ({url}): {exc}") from exc


def write_output(name: str, value: str) -> None:
    if not GITHUB_OUTPUT:
        return

    with open(GITHUB_OUTPUT, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def write_verdict(data: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    VERDICT_FILE.parent.mkdir(parents=True, exist_ok=True)

    VERDICT_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def fail_review(reason: str) -> None:
    log(f"ERROR: {reason}")

    verdict = {
        "repository": REPOSITORY,
        "pr_number": int(PR_NUMBER) if PR_NUMBER.isdigit() else PR_NUMBER,
        "head_sha": HEAD_SHA,
        "control": "ai-review",
        "status": "fail",
        "detail": reason[:1000],
        "metrics": {},
        "review_status": "not_completed",
        "result": "error",
        "reason": reason,
    }

    write_verdict(verdict)
    write_output("result", json.dumps({"status": "fail", "detail": reason[:500], "metrics": {}}))

    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Retrieve authenticated PR context
# ---------------------------------------------------------------------------

def retrieve_pr_context() -> dict:
    log(
        f"Retrieving authenticated PR context for "
        f"{REPOSITORY}#{PR_NUMBER}"
    )

    diff = run_gh(
        "pr",
        "diff",
        PR_NUMBER,
        "--repo",
        REPOSITORY,
    )

    changed_files_raw = run_gh(
        "pr",
        "diff",
        PR_NUMBER,
        "--repo",
        REPOSITORY,
        "--name-only",
    )

    changed_files = [
        line.strip()
        for line in changed_files_raw.splitlines()
        if line.strip()
    ]

    diff_bytes = len(diff.encode("utf-8"))

    diff_sha256 = hashlib.sha256(
        diff.encode("utf-8")
    ).hexdigest()

    if not diff.strip():
        return {
            "source": "github-actions-authenticated",
            "diff_status": "unavailable",
            "reason": "GitHub returned an empty PR diff.",
            "changed_files": "\n".join(changed_files),
            "file_count": len(changed_files),
            "diff_bytes": diff_bytes,
            "diff_sha256": diff_sha256,
            "pr_diff": "",
        }

    if diff_bytes > MAX_DIFF_BYTES:
        return {
            "source": "github-actions-authenticated",
            "diff_status": "too_large",
            "reason": (
                f"PR diff is {diff_bytes} bytes, exceeding "
                f"the configured limit of {MAX_DIFF_BYTES} bytes."
            ),
            "changed_files": "\n".join(changed_files),
            "file_count": len(changed_files),
            "diff_bytes": diff_bytes,
            "diff_sha256": diff_sha256,
            "pr_diff": "",
        }

    return {
        "source": "github-actions-authenticated",
        "diff_status": "available",
        "reason": "",
        "changed_files": "\n".join(changed_files),
        "file_count": len(changed_files),
        "diff_bytes": diff_bytes,
        "diff_sha256": diff_sha256,
        "pr_diff": diff,
    }


# ---------------------------------------------------------------------------
# Build and send signed Hermes webhook
# ---------------------------------------------------------------------------

def load_event() -> dict:
    with open(GITHUB_EVENT_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_payload() -> tuple[dict, bytes]:
    event = load_event()

    # pull_request_review events carry the PR only under `pull_request`, but the
    # Hermes route addresses its comment with {number}: without this top-level
    # field the gateway reviews the diff and then cannot deliver the result
    # ("invalid pr_number: '{number}'").
    if PR_NUMBER.isdigit():
        event.setdefault("number", int(PR_NUMBER))

    context = retrieve_pr_context()

    event["hermes_context"] = context

    payload_bytes = json.dumps(
        event,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return event, payload_bytes


def sign_payload(payload_bytes: bytes) -> str:
    digest = hmac.new(
        HERMES_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    return f"sha256={digest}"


def send_to_hermes(payload_bytes: bytes) -> None:
    signature = sign_payload(payload_bytes)

    run_id = os.environ.get("GITHUB_RUN_ID", "unknown")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")

    # The gateway de-duplicates on this id for an hour (a repeat gets HTTP 200
    # {"status": "duplicate"} and no second agent run). It identifies the REVIEW
    # being asked for, not the workflow run: a pull_request run and the
    # pull_request_review run that cancels it are two runs for one commit, and
    # keying on the run id made Hermes review, and comment, twice. The attempt
    # number keeps a deliberate re-run of the same commit a fresh request.
    repo_slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", REPOSITORY)
    delivery = f"gha-{repo_slug}-pr{PR_NUMBER}-{HEAD_SHA[:12]}-a{run_attempt}"

    request = urllib.request.Request(
        _http_url(HERMES_URL),
        data=payload_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": signature,
            "User-Agent": "Tiberbu-Hermes-Security-Review/1.0",
        },
    )

    log(f"Sending signed review payload to Hermes ({delivery})")
    global SENT_AT
    SENT_AT = dt.datetime.now(dt.timezone.utc)

    try:
        with urllib.request.urlopen(  # nosemgrep: dynamic-urllib-use-detected -- scheme checked by _http_url
            request,
            timeout=60,
        ) as response:
            response_body = response.read().decode(
                "utf-8",
                errors="replace",
            )

            log(
                f"Hermes accepted webhook: "
                f"HTTP {response.status}"
            )

            if response_body:
                log(
                    f"Hermes response: "
                    f"{response_body[:500]}"
                )

            if '"duplicate"' in response_body:
                log(
                    "Hermes already has a review requested for this commit "
                    "(another run asked first); waiting for that review instead "
                    "of asking again"
                )

    except urllib.error.HTTPError as exc:
        body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            f"Hermes returned HTTP {exc.code}: {body}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Unable to reach Hermes: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Wait for Hermes PR comment
# ---------------------------------------------------------------------------
def get_comments() -> list:
    raw = run_gh(
        "api",
        f"repos/{REPOSITORY}/issues/{PR_NUMBER}/comments?per_page=100",
    )

    parsed = json.loads(raw)

    if not isinstance(parsed, list):
        raise RuntimeError(
            "GitHub comments API returned an unexpected response."
        )

    return parsed


SENT_AT: "dt.datetime | None" = None  # when this run asked Hermes (set by send_to_hermes)


def matching_comment(comment: dict) -> bool:
    body = comment.get("body") or ""

    # A first attempt may share the review another run for this commit already
    # asked for, so any comment for the commit counts. A deliberate re-run
    # (attempt > 1) asked for a NEW review: only a comment posted after the
    # request is that review, never the one from before.
    if SENT_AT and os.environ.get("GITHUB_RUN_ATTEMPT", "1") != "1":
        try:
            created = dt.datetime.fromisoformat(str(comment.get("created_at", "")).replace("Z", "+00:00"))
        except ValueError:
            return False
        if created < SENT_AT - dt.timedelta(seconds=5):
            return False

    user = (
        comment.get("user") or {}
    ).get("login", "")

    if HERMES_COMMENTER and user != HERMES_COMMENTER:
        return False

    if "Automated review by Hermes" not in body:
        return False

    if HEAD_SHA and HEAD_SHA not in body:
        return False

    return True


def wait_for_review_comment() -> dict:
    deadline = time.time() + WAIT_SECONDS

    log(
        f"Waiting up to {WAIT_SECONDS}s for Hermes "
        f"to post the review"
    )

    while time.time() < deadline:
        comments = get_comments()

        matches = [
            comment
            for comment in comments
            if matching_comment(comment)
        ]

        if matches:
            matches.sort(
                key=lambda item: item.get(
                    "created_at",
                    "",
                )
            )

            return matches[-1]

        time.sleep(15)

    raise TimeoutError(
        f"No Hermes review comment found after "
        f"{WAIT_SECONDS} seconds."
    )


# ---------------------------------------------------------------------------
# Parse the review comment
# ---------------------------------------------------------------------------
# The PR comment format is owned by the route prompt (hermes-route.yaml) and
# is deliberately unchanged:
#   Security review: <N> finding(s)
#   ## Security findings
#   ### [F1] <title> (Severity: Critical)
#   - CWE: 89
#   - Location: path/to/file.py:42
#   - Description: ...
#   - Impact: ...
#   - Mitigation: ...
# followed by "## Schema / database changes", "## Dependency / library
# changes" and "## Other notes". Everything below is derived from it.

BLOCKING = {"critical", "high"}
MAX_FINDINGS = 50
MAX_FIELD_CHARS = 2000
MAX_TITLE_CHARS = 200

FINDING_HEADER = re.compile(
    r"^###\s*\[(?P<id>F\d+)\]\s*(?P<title>.+?)\s*"
    r"\(Severity:\s*(?P<severity>Critical|High|Medium|Low)\)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
FIELD_LINE = re.compile(
    r"^-\s*(?P<label>OWASP|CWE|Location|CVSS|Evidence|Business context|Business adjustment|Description|Impact|Mitigation)\s*:\s*(?P<value>.*)$",
    re.IGNORECASE | re.MULTILINE,
)
FILE_LINE = re.compile(r"^(?P<path>.+?):(?P<line>\d+)(?:-\d+)?$")
SECTION_END = re.compile(r"^(---\s*$|##\s)", re.MULTILINE)
COUNT_HEADER = re.compile(r"^Security review:\s*(\d+)\s+finding", re.IGNORECASE)
NOT_COMPLETED = re.compile(r"^Security review:\s*not completed", re.IGNORECASE)
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def _clean(text: str, max_chars: int) -> str:
    """Strip control characters and cap the length: this text lands in JSON
    that DefectDojo imports, so one comment can't inject unbounded content."""
    return "".join(ch for ch in text if ch == "\n" or ch >= " ")[:max_chars]


def _section(body: str, heading: str) -> str:
    start = body.find(heading)
    if start == -1:
        return ""
    rest = body[start + len(heading):]
    end = SECTION_END.search(rest)
    return rest[: end.start()] if end else rest


def parse_findings(body: str) -> list[dict]:
    """One dict per '### [Fn] title (Severity: X)' block of the findings
    section. A field the model omitted is left out, never guessed."""

    section = _section(body, "## Security findings")
    headers = list(FINDING_HEADER.finditer(section))[:MAX_FINDINGS]
    findings = []

    for i, match in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(section)
        fields = {
            f.group("label").lower(): f.group("value").strip()
            for f in FIELD_LINE.finditer(section[match.end():end])
        }

        finding = {
            "id": match.group("id").upper(),
            "title": _clean(match.group("title").strip(), MAX_TITLE_CHARS),
            "severity": match.group("severity").title(),
            "owasp": _clean(fields.get("owasp", ""), MAX_TITLE_CHARS),
            "cvss": fields.get("cvss", "").strip(),
            "evidence": _clean(fields.get("evidence", ""), MAX_FIELD_CHARS),
            "business_context": _clean(fields.get("business context", ""), MAX_FIELD_CHARS),
            "business_adjustment": _clean(fields.get("business adjustment", ""), MAX_FIELD_CHARS),
            "cwe": None,
            "file": "",
            "line": None,
            "description": _clean(fields.get("description") or match.group("title"), MAX_FIELD_CHARS),
            "impact": _clean(fields.get("impact", ""), MAX_FIELD_CHARS),
            "mitigation": _clean(fields.get("mitigation", ""), MAX_FIELD_CHARS),
        }

        cwe = re.search(r"\d+", fields.get("cwe", ""))
        if cwe:
            finding["cwe"] = int(cwe.group())

        location = fields.get("location", "")
        loc = FILE_LINE.match(location)
        if loc:
            finding["file"] = _clean(loc.group("path"), MAX_TITLE_CHARS)
            finding["line"] = int(loc.group("line"))
        elif location and location.upper() != "N/A":
            finding["file"] = _clean(location, MAX_TITLE_CHARS)

        findings.append(finding)

    return findings


CVSS_FIELD = re.compile(
    r"^(?P<vector>CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/"
    r"VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN])\s*(?:\(?\s*(?P<score>\d{1,2}(?:\.\d)?)\s*\)?)?",
)
SCORE_BY_SEVERITY = {"Critical": 9.5, "High": 8.0, "Medium": 5.5, "Low": 3.0}  # SARIF fallback only
RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def band(score: float) -> str:
    return "Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"


def assess_finding(finding: dict) -> None:
    """Hermes assigns the severity: the `(Severity: X)` heading label is what is
    reported. Because that comment is model output produced from untrusted PR
    content, three cheap integrity checks run on it (none recalculates CVSS):

      * the CVSS v4.0 vector and the score Hermes stated must be present and
        well-formed, otherwise the finding is flagged;
      * a label BELOW the band of Hermes's own stated score is flagged, and when
        that band is Critical/High (the blocking levels) the severity is raised
        to it, i.e. an inconsistency can only ever make the gate stricter;
      * flags travel with the finding into the report, DefectDojo and the job
        summary, so a downgrade is visible to a human instead of silent."""

    match = CVSS_FIELD.match(finding["cvss"].strip())
    finding["cvss_vector"] = match.group("vector") if match else ""
    finding["cvss_score"] = float(match.group("score")) if match and match.group("score") else None
    finding["unconfirmed"] = finding["evidence"].strip().lower().startswith("not confirmed")
    finding["hermes_label"] = finding["severity"]
    flags = []

    if not finding["cvss_vector"]:
        flags.append("CVSS v4.0 vector missing or malformed")
    if finding["cvss_score"] is None:
        flags.append("CVSS score not stated")
    elif not 0.0 < finding["cvss_score"] <= 10.0:
        flags.append(f"stated CVSS score {finding['cvss_score']} out of range")
        finding["cvss_score"] = None
    if not finding["evidence"].strip():
        flags.append("Evidence missing")

    if finding["cvss_score"] is not None:
        stated = band(finding["cvss_score"])
        if RANK[stated] > RANK[finding["severity"]]:
            if stated in ("Critical", "High"):
                flags.append(f"labelled {finding['severity']} but its own score {finding['cvss_score']} is {stated}: raised to {stated}")
                finding["severity"] = stated
            else:
                flags.append(f"labelled {finding['severity']} but its own score {finding['cvss_score']} is {stated} (flag only)")
    finding["flags"] = flags


def parse_review(comment: dict) -> dict:
    """Verdict inputs from the comment. Fails closed: a comment whose own
    'N finding(s)' header disagrees with the blocks parsed is an error, so a
    format drift can never again turn nine findings into a clean pass."""

    body = comment.get("body") or ""
    first = body.strip().splitlines()[0].strip() if body.strip() else ""
    counts = {s: 0 for s in SEVERITY_ORDER}

    if NOT_COMPLETED.match(first):
        return {"status": "not_completed", "result": "error", "blocking_findings": 0,
                "severity_counts": counts, "findings": [],
                "detail": "Hermes could not complete the review (no diff to review)"}

    findings = parse_findings(body)
    for finding in findings:
        assess_finding(finding)

    declared = COUNT_HEADER.match(first)
    if declared and int(declared.group(1)) != len(findings):
        return {"status": "not_completed", "result": "error", "blocking_findings": 0,
                "severity_counts": counts, "findings": findings,
                "detail": f"comment declares {declared.group(1)} finding(s) but {len(findings)} were parsed — "
                          "comment format changed; refusing to pass"}

    if findings and not any(f["cvss_vector"] and f["cvss_score"] is not None for f in findings):
        return {"status": "not_completed", "result": "error", "blocking_findings": 0,
                "severity_counts": counts, "findings": findings,
                "detail": f"none of the {len(findings)} finding(s) carries a valid CVSS v4.0 vector and score: "
                          "the review did not follow the severity method; refusing to pass"}

    for finding in findings:
        counts[finding["severity"]] += 1
    blocking = counts["Critical"] + counts["High"]
    return {"status": "completed", "result": "fail" if blocking else "pass",
            "blocking_findings": blocking, "severity_counts": counts,
            "findings": findings, "detail": ""}


# ---------------------------------------------------------------------------
# Reports: DefectDojo Generic Findings Import, SARIF, markdown
# ---------------------------------------------------------------------------

SARIF_LEVEL_BY_SEVERITY = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}  # SARIF 2.1.0 levels; the CVSS score rides in security-severity


def _location(finding: dict) -> str:
    if not finding["file"]:
        return "not stated"
    return f"{finding['file']}:{finding['line']}" if finding["line"] else finding["file"]


def build_defectdojo_findings(findings: list[dict], comment_url: str) -> dict:
    """DefectDojo 'Generic Findings Import' JSON, filled in like the AI
    SAST/DAST sample (test 17): bracketed source id in the title, structured
    description, mitigation, impact, references, CWE, file and line, the
    static_finding flag for SAST classification, and a stable
    unique_id_from_tool so a re-run on a newer commit reimports (closing what
    was fixed) instead of duplicating."""

    today = time.strftime("%Y-%m-%d", time.gmtime())
    pr_url = f"https://github.com/{REPOSITORY}/pull/{PR_NUMBER}"
    references = [f"Hermes AI security review of {REPOSITORY}#{PR_NUMBER} at commit {HEAD_SHA}", pr_url]
    if comment_url:
        references.append(comment_url)

    out = []
    seen_keys: dict = {}
    for finding in sorted(findings, key=lambda f: (f["file"], f["line"] or 0, f["id"])):
        basis = (f"CVSS v4.0 base score {finding['cvss_score']}" if finding["cvss_score"] is not None
                 else "CVSS v4.0 score not stated")
        parts = [
            f"**Source finding ID:** {finding['id']} (Hermes AI security review, PR #{PR_NUMBER}, "
            f"commit `{HEAD_SHA[:12]}`)",
            f"**Location:** `{_location(finding)}`",
            f"**Classification:** {finding['owasp'] or 'OWASP: n/a'}; "
            f"{'CWE-' + str(finding['cwe']) if finding['cwe'] else 'CWE: n/a'}",
            f"**Severity basis:** {basis}, vector `{finding['cvss_vector'] or finding['cvss'] or 'not stated'}`. "
            f"Business adjustment: {finding['business_adjustment'] or 'none'}. "
            f"Severity: {finding['severity']} (assigned by Hermes)."
            + (f" Integrity flags: {'; '.join(finding['flags'])}." if finding["flags"] else ""),
            f"**Exploitability evidence:** {finding['evidence']}",
            f"**Business context:** {finding['business_context']}",
            finding["description"],
        ]
        description = "\n\n".join(parts)
        # Identity ignores the free-text title (a reworded re-review must reimport, not duplicate);
        # two findings of one class in one file are told apart by their order in the file.
        key = (finding["file"], finding["cwe"], finding["owasp"].split(" ")[0].upper())
        seen_keys[key] = seen_keys.get(key, 0) + 1
        identity = "|".join([REPOSITORY, finding["file"], str(finding["cwe"] or ""), key[2], str(seen_keys[key])])
        item = {
            "title": f"[{finding['id']}] {finding['title']}"[:MAX_TITLE_CHARS],
            "severity": finding["severity"],
            "description": description,
            "mitigation": finding["mitigation"],
            "impact": finding["impact"],
            "references": "\n".join(references),
            "static_finding": True,
            "dynamic_finding": False,
            "active": True,
            "verified": False,
            "date": today,
            "unique_id_from_tool": "hermes-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
            "tags": ["ai-sast", "hermes", f"pr-{PR_NUMBER}"]
                    + (["unconfirmed"] if finding.get("unconfirmed") else [])
                    + (["severity-flagged"] if finding["flags"] else [])
                    + ([re.sub(r"[^a-z0-9]+", "-", finding["owasp"].split()[0].lower()).strip("-")]
                       if finding["owasp"] and finding["owasp"].upper() != "N/A" else []),
            "cvssv4": finding["cvss_vector"],
            "cvssv4_score": finding["cvss_score"],
        }
        if finding["file"]:
            item["file_path"] = finding["file"]
        if finding["line"]:
            item["line"] = finding["line"]
        if finding["cwe"]:
            item["cwe"] = finding["cwe"]
            item["vuln_id_from_tool"] = f"CWE-{finding['cwe']}"
        out.append({k: v for k, v in item.items() if v not in ("", None)})

    return {"findings": out}


def build_sarif(findings: list[dict]) -> dict:
    """SARIF 2.1.0 for the review findings (level/ruleId/physicalLocation).
    The rule id encodes the severity."""

    rules, seen, results = [], set(), []
    for finding in findings:
        rule_id = "hermes.ai-review." + finding["severity"].lower()
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f"Hermes AI security review finding ({finding['severity']})",
                "shortDescription": {"text": f"{finding['severity']} finding reported by the Hermes AI security review"},
            })
        text = f"[{finding['id']}] {finding['title']}. {finding['description']}"
        if finding["mitigation"]:
            text += f" Suggested fix: {finding['mitigation']}"
        result = {"ruleId": rule_id, "level": SARIF_LEVEL_BY_SEVERITY[finding["severity"]],
                  "message": {"text": text},
                  "properties": {"security-severity": str(
                                     finding["cvss_score"]
                                     if finding["cvss_score"] is not None and band(finding["cvss_score"]) == finding["severity"]
                                     else SCORE_BY_SEVERITY[finding["severity"]]),
                                 "cvssV4": finding["cvss_vector"], "owasp": finding["owasp"],
                                 "cwe": finding["cwe"]}}
        if finding["file"]:
            physical = {"artifactLocation": {"uri": finding["file"]}}
            if finding["line"]:
                physical["region"] = {"startLine": finding["line"]}
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "Hermes AI Security Review", "version": "1.0", "rules": rules}},
                  "results": results}],
    }


def build_markdown_report(assessment: dict, comment: dict, context: dict) -> str:
    """Human-readable report: scope, severity table, every finding in full,
    then the comment's schema / dependency / notes sections verbatim."""

    body = comment.get("body") or ""
    counts = assessment["severity_counts"]
    lines = [
        f"# Hermes AI security review — {REPOSITORY}#{PR_NUMBER}",
        "",
        f"- Commit: `{HEAD_SHA}`",
        *([f"- **Not rated:** {assessment['detail']}"] if assessment.get("detail") else []),
        f"- Result: **{assessment['result'].upper()}** "
        f"({assessment['blocking_findings']} Critical/High blocking)",
        f"- Diff reviewed: {context['file_count']} file(s), {context['diff_bytes']} bytes, "
        f"sha256 `{context['diff_sha256']}`",
        f"- PR comment: {comment.get('html_url', '')}",
        "",
        "| Severity | Findings |", "|---|---|",
        *[f"| {s} | {counts[s]} |" for s in SEVERITY_ORDER],
        "",
        "## Findings",
        "",
    ]
    for finding in sorted(assessment["findings"], key=lambda f: SEVERITY_ORDER.index(f["severity"])):
        lines += [
            f"### [{finding['id']}] {finding['title']} ({finding['severity']})",
            "",
            f"- **OWASP:** {finding['owasp'] or 'n/a'}  **CWE:** {finding['cwe'] or 'n/a'}",
            f"- **Location:** `{_location(finding)}`",
            f"- **CVSS v4.0:** {finding['cvss_score'] if finding['cvss_score'] is not None else 'score not stated'} `{finding['cvss_vector'] or finding['cvss'] or 'not stated'}`",
            f"- **Severity:** {finding['severity']} (assigned by Hermes)"
            + (f" — **flags:** {'; '.join(finding['flags'])}" if finding["flags"] else ""),
            f"- **Exploitability evidence:** {finding['evidence']}",
            f"- **Business context:** {finding['business_context']}",
            f"- **Business adjustment:** {finding['business_adjustment']}",
            f"- **Description:** {finding['description']}",
            f"- **Impact:** {finding['impact'] or 'n/a'}",
            f"- **Mitigation:** {finding['mitigation'] or 'n/a'}",
            "",
        ]
    for heading in ("## Schema / database changes", "## Dependency / library changes", "## Other notes"):
        text = _section(body, heading).strip()
        if text:
            lines += [heading, "", text, ""]
    return "\n".join(lines)


def write_reports(assessment: dict, comment: dict, context: dict) -> list[str]:
    """Writes into $OUT (uploaded as artifact report-ai-review/, from which
    defectdojo_upload.py imports hermes-findings.json). Written even with
    zero findings so a clean run still shows as an imported, empty test."""

    OUT.mkdir(parents=True, exist_ok=True)
    findings = assessment["findings"]
    if assessment["status"] != "completed":
        # No machine-readable files for a review that could not be rated: with
        # close_old_findings, an empty or partial import would tell DefectDojo
        # that everything reported before had been fixed.
        (OUT / "hermes-report.md").write_text(
            build_markdown_report(assessment, comment, context) + "\n", encoding="utf-8")
        return ["hermes-report.md"]
    files = {
        "hermes-findings.json": json.dumps(
            build_defectdojo_findings(findings, comment.get("html_url") or ""), indent=2, ensure_ascii=False),
        "ai-review.sarif": json.dumps(build_sarif(findings), indent=2, ensure_ascii=False),
        "hermes-report.md": build_markdown_report(assessment, comment, context),
    }
    for name, content in files.items():
        (OUT / name).write_text(content + "\n", encoding="utf-8")
    return sorted(files)


def finish(status: str, detail: str, **metrics) -> None:
    """The gate reads `result` as JSON {status, detail, metrics} (gate.py); a
    bare string reads as 'control did not complete'."""
    result = {"status": status, "detail": detail[:1000], "metrics": metrics}
    write_output("result", json.dumps(result))
    # verdict.json carries the same {control, status, detail, metrics} every
    # control's verdict has (the PR findings comment and findings tooling read
    # it) next to the review's own fields (result, blocking_findings, ...).
    try:
        current = json.loads(VERDICT_FILE.read_text(encoding="utf-8")) if VERDICT_FILE.exists() else {}
    except (OSError, ValueError):
        current = {}
    if "status" in current:
        current["review_status"] = current.pop("status")
    current.update({"control": "ai-review", **result})
    write_verdict(current)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"### AI security review · Hermes: {status}\n\n{detail}\n")
    if status != "pass":
        print(f"::error::{detail[:500]}")
    raise SystemExit(0 if status == "pass" else 1)  # a verdict is final


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not REPOSITORY:
        fail_review("REPOSITORY/GITHUB_REPOSITORY is not set.")

    if not PR_NUMBER:
        fail_review("PR_NUMBER is not set.")

    if not HEAD_SHA:
        fail_review("HEAD_SHA is not set.")

    if not HERMES_URL:
        fail_review("HERMES_URL is not set.")

    if not HERMES_SECRET:
        fail_review("HERMES_SECRET is not set.")

    if not HERMES_COMMENTER:
        # The verdict is read from a PR comment; without a pinned author, anyone
        # who can comment could post a fake "Automated review by Hermes".
        fail_review("HERMES_COMMENTER is not set: refusing to trust an unauthenticated review comment.")

    try:
        event, payload_bytes = build_payload()

        context = event["hermes_context"]

        log(
            "PR context: "
            f"status={context['diff_status']} "
            f"files={context['file_count']} "
            f"bytes={context['diff_bytes']} "
            f"sha256={context['diff_sha256'][:12]}..."
        )

        send_to_hermes(payload_bytes)

        comment = wait_for_review_comment()

        assessment = parse_review(comment)

        written = write_reports(assessment, comment, context)
        log(f"Reports written to {OUT}: {', '.join(written)} "
            f"({len(assessment['findings'])} finding(s))")

        verdict = {
            "repository": REPOSITORY,
            "pr_number": int(PR_NUMBER),
            "head_sha": HEAD_SHA,
            "source": "github-actions-authenticated",
            "diff_status": context["diff_status"],
            "diff_bytes": context["diff_bytes"],
            "file_count": context["file_count"],
            "diff_sha256": context["diff_sha256"],
            "review_status": assessment["status"],
            "result": assessment["result"],
            "blocking_findings": assessment["blocking_findings"],
            "severity_counts": assessment["severity_counts"],
            "comment_url": comment.get("html_url"),
        }
        write_verdict(verdict)

        counts = assessment["severity_counts"]
        summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]) or "no findings"
        flagged = [f["id"] for f in assessment["findings"] if f["flags"]]
        if flagged:
            summary += f" ({len(flagged)} flagged: {', '.join(flagged)}, see hermes-report.md)"
        link = comment.get("html_url") or ""
        log(f"Review completed: result={assessment['result']} blocking_findings={assessment['blocking_findings']}")

        if assessment["result"] == "error":
            finish("fail", assessment["detail"], findings=0)
        if assessment["result"] == "fail":
            finish("fail", f"Hermes: {summary} — Critical/High block the merge; see {link}",
                   findings=len(assessment["findings"]), blocking=assessment["blocking_findings"])
        finish("pass", f"Hermes: {summary}; no Critical/High; see {link}",
               findings=len(assessment["findings"]), blocking=0)

    except Exception as exc:
        fail_review(str(exc))


if __name__ == "__main__":
    main()
