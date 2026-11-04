#!/usr/bin/env python3

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
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

GH_BIN = "gh"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    print(f"[hermes-review] {message}", flush=True)


def run_gh(*args: str, timeout: int = 120) -> str:
    """
    Execute a read-only GitHub CLI command using the workflow's GITHUB_TOKEN.
    """

    env = os.environ.copy()
    env["GH_TOKEN"] = GH_TOKEN

    result = subprocess.run(
        [GH_BIN, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"gh {' '.join(args)} failed "
            f"(exit={result.returncode}): "
            f"{result.stderr.strip()}"
        )

    return result.stdout


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
        "status": "not_completed",
        "result": "error",
        "reason": reason,
    }

    write_verdict(verdict)
    write_output("result", "error")

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

    delivery = f"gha-{run_id}-{run_attempt}"

    request = urllib.request.Request(
        HERMES_URL,
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

    try:
        with urllib.request.urlopen(
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


def matching_comment(comment: dict) -> bool:
    body = comment.get("body") or ""

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
# Parse security result
# ---------------------------------------------------------------------------

SEVERITY_RE = re.compile(
    r"^\|\s*"
    r"(Critical|High|Medium|Low)"
    r"\s*\|",
    re.IGNORECASE | re.MULTILINE,
)


def parse_review(comment: dict) -> dict:
    body = comment.get("body") or ""

    first_line = (
        body.strip().splitlines()[0]
        if body.strip()
        else ""
    )

    if first_line.strip().lower() == \
            "security review: not completed":

        return {
            "status": "not_completed",
            "result": "error",
            "blocking_findings": 0,
            "severity_counts": {},
        }

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for match in SEVERITY_RE.finditer(body):
        severity = match.group(1).capitalize()
        severity_counts[severity] += 1

    blocking = (
        severity_counts["Critical"]
        + severity_counts["High"]
    )

    result = "fail" if blocking else "pass"

    return {
        "status": "completed",
        "result": result,
        "blocking_findings": blocking,
        "severity_counts": severity_counts,
    }


# ---------------------------------------------------------------------------
# Parse the findings table (per-finding detail for ai-review.sarif)
# ---------------------------------------------------------------------------

FINDING_ROW_RE = re.compile(
    r"^\|\s*(Critical|High|Medium|Low)\s*\|"
    r"\s*([^|]+?)\s*\|"
    r"\s*([^|]*?)\s*\|"
    r"\s*([^|]*?)\s*\|\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def parse_findings(body: str) -> list[dict]:
    """The security-findings table of the review comment as per-finding
    dicts (severity, file, line, issue, fix)."""

    findings = []

    for match in FINDING_ROW_RE.finditer(body):
        severity = match.group(1).capitalize()
        location = match.group(2).strip()

        file, sep, line = location.rpartition(":")
        if sep and line.isdigit():
            file = file.strip() or location
            line = int(line)
        else:
            file, line = location, None

        findings.append({
            "severity": severity,
            "file": file,
            "line": line,
            "issue": match.group(3).strip(),
            "fix": match.group(4).strip(),
        })

    return findings


SARIF_LEVEL_BY_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "warning",
    "Low": "note",
}


def build_sarif(findings: list[dict]) -> dict:
    """SARIF 2.1.0 for the review findings. Consumed by pr_findings.py /
    gate_findings.py through the standard SARIF path (level/ruleId/
    physicalLocation) and, later, by the DefDojo reimport-scan. The rule id
    encodes the severity (the renderer's AI-review key carries the location
    and message, so same-file findings never collapse)."""

    rules = []
    seen = set()
    for finding in findings:
        rule_id = "hermes.ai-review." + finding["severity"].lower()
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": "Hermes AI security review finding ("
                         + finding["severity"] + ")",
                "shortDescription": {
                    "text": finding["severity"]
                             + " finding reported by the Hermes AI security "
                               "review",
                },
            })

    results = []
    for finding in findings:
        text = finding["issue"]
        if finding["fix"]:
            text = (text + " Suggested fix: " + finding["fix"]).strip()
        physical = {"artifactLocation": {"uri": finding["file"]}}
        if finding["line"]:
            physical["region"] = {"startLine": finding["line"]}
        results.append({
            "ruleId": "hermes.ai-review." + finding["severity"].lower(),
            "level": SARIF_LEVEL_BY_SEVERITY[finding["severity"]],
            "message": {"text": text},
            "locations": [{"physicalLocation": physical}],
        })

    return {
        "version": "2.1.0",
        "$schema":
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Hermes AI Security Review",
                    "informationUri": "https://hermes.usfali.com",
                    "version": "1.0",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def write_sarif(findings: list[dict]) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "ai-review.sarif"
    path.write_text(
        json.dumps(build_sarif(findings), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


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

        if assessment["status"] == "completed":
            findings = parse_findings(comment.get("body") or "")
            sarif_path = write_sarif(findings)
            log(
                f"Findings persisted: {len(findings)} "
                f"-> {sarif_path}"
            )

        verdict = {
            "repository": REPOSITORY,
            "pr_number": int(PR_NUMBER),
            "head_sha": HEAD_SHA,

            "source": "github-actions-authenticated",

            "diff_status": context["diff_status"],
            "diff_bytes": context["diff_bytes"],
            "file_count": context["file_count"],
            "diff_sha256": context["diff_sha256"],

            "status": assessment["status"],
            "result": assessment["result"],
            "blocking_findings": assessment[
                "blocking_findings"
            ],
            "severity_counts": assessment[
                "severity_counts"
            ],

            "comment_url": comment.get("html_url"),
        }

        write_verdict(verdict)

        write_output(
            "result",
            assessment["result"],
        )

        log(
            "Review completed: "
            f"result={assessment['result']} "
            f"blocking_findings="
            f"{assessment['blocking_findings']}"
        )

        if assessment["result"] == "error":
            raise SystemExit(1)

        # Findings are advisory — Critical/High can be enforced by a
        # separate gate using the 'result' job output.
        raise SystemExit(0)

    except Exception as exc:
        fail_review(str(exc))


if __name__ == "__main__":
    main()
