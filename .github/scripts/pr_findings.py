#!/usr/bin/env python3
"""PR findings comment for the frappe-gates-demo release pipeline
(the facility360 devsecops standard, ported - one pipeline per app).

Reads THIS run's develop-phase report artifacts (downloaded to ./reports by
the pr-comment job), counts findings per control, diffs them against the
baseline (the latest SUCCESSFUL release run on the base branch, fetched via
the GitHub API), and posts/updates one marker-anchored comment on the PR.
The comment lists ONLY the CRITICAL/HIGH findings (the blocking band) plus
the per-control counts; the full list of every finding (all severities) is
written to the job's step Summary, which the comment points to.

Gate: REPORT-ONLY for CRITICAL/HIGH findings (the hmis policy 2026-10-28,
the facility360 policy 2026-10-29, adopted by this app - the app does not
block on findings). The check still fails (fail-closed) when a required
report is missing or ungradeable, or a graded control did not succeed.

Environment:
  GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_API_URL (optional) - the job env
  PR_NUMBER, BASE_BRANCH - set by the workflow step
  GATE_NEEDS - JSON map of this job's needs (job -> {result, outputs}); the
  gate verdict section evaluates the develop controls fail-closed, the same
  logic the G2 gate job runs on release runs

Exit: 0 when the comment is posted and the gate passes (every graded
control successful - CRITICAL/HIGH findings are reported, never blocking).
Non-zero when a required report is missing or ungradeable, or a graded
control did not succeed (the comment is posted FIRST, then the run fails
so the PR check goes red) or on hard errors (API/token/report parsing) -
a feedback job that silently does nothing is worse than a red step.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request
from defusedxml import ElementTree as ET  # defusedxml: no DTD/external-entity handling (semgrep use-defused-xml-parse)
import zipfile
import tempfile

# the shared CRITICAL/HIGH severity grading (the G2 gate uses the same
# module via its CLI entry point - one canonical implementation)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_findings  # noqa: E402

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
PR = os.environ.get("PR_NUMBER", "")
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main")
WORKFLOW_NAME = "devsecops pipeline"
# a DISTINCT marker from this repo's own gate-ladder comment
# ("<!-- devsecops-findings -->", used by devsecops-pipeline.yml's
# pr-comment job): the two workflows post independent comments.
MARKER = "<!-- devsecops-findings:release-pipeline -->"

REPORTS_DIR = os.path.join(os.getcwd(), "reports")

# Report files the PR findings gate requires (flat artifact layout - the
# merge-multiple download places the zip-root files directly in ./reports).
# This app runs the IaC + unit-test controls on PR runs too (the Dockerfile
# and the bench suite are in the checkout), so checkov.sarif + junit.xml
# are required here.
# NOTE: "thufflehog.json" (not trufflehog.json) is the real report name -
# the workflow's trufflehog-scan call writes that file.
PR_REQUIRED_REPORTS = [
    "semgrep.json",
    "gitleaks.json",
    "thufflehog.json",
    "ruff.json",
    "checkov.sarif",
    "trivy-fs.sarif",
    "junit.xml",
]


def api(method, path, data=None):
    url = f"{API}{path}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "devsecops-findings")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"API {method} {path} -> HTTP {e.code}: {detail}") from e


# ── per-control report counters ──────────────────────────────────────────

def count_semgrep(path):
    d = json.load(open(path))
    return len(d.get("results", []))


def count_gitleaks(path):
    d = json.load(open(path))
    if isinstance(d, list):
        return len(d)
    return len(d.get("Leaks", d.get("findings", [])))


def count_ndjson(path):
    n = 0
    with open(path) as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n


def count_ruff(path):
    d = json.load(open(path))
    return len(d) if isinstance(d, list) else len(d.get("results", []))


def count_sarif(path):
    d = json.load(open(path))
    n = 0
    for run in d.get("runs", []):
        n += len(run.get("results", []))
    return n


def count_junit(path):
    """Returns (tests, failures+errors)."""
    tree = ET.parse(path)
    root = tree.getroot()
    suites = [root] if root.tag == "testsuite" else root.findall(".//testsuite")
    tests = fails = 0
    for s in suites:
        tests += int(s.get("tests", 0) or 0)
        fails += int(s.get("failures", 0) or 0) + int(s.get("errors", 0) or 0)
    return (tests, fails)


# (label, artifact name, file inside the artifact, counter, unit)
CONTROLS = [
    ("SAST (semgrep)", "report-sast", "sast/semgrep.json", count_semgrep, "findings"),
    ("Secrets (gitleaks, full history)", "report-secrets", "secrets/gitleaks.json", count_gitleaks, "findings"),
    ("Secrets (trufflehog, verified)", "report-secrets-th", "secrets-th/thufflehog.json", count_ndjson, "findings"),
    ("Quality (ruff, repo config)", "report-quality", "quality/ruff.json", count_ruff, "findings"),
    ("IaC (checkov, Dockerfile)", "report-iac", "iac/checkov.sarif", count_sarif, "failures"),
    ("SCA (trivy fs, HIGH/CRIT)", "report-sca", "sca/trivy-fs.sarif", count_sarif, "vulnerabilities"),
    ("Unit tests (bench suite, real MariaDB)", "report-unit-tests", "unit-tests/junit.xml", count_junit, "tests"),
]


def count_in_dir(dirpath, control):
    """Count findings for one control inside an extracted artifact dir.

    Returns (value, display) - value may be None when the report is missing
    (the control crashed / produced no report).
    """
    _label, _art, rel, counter, unit = control
    path = os.path.join(dirpath, rel)
    if not os.path.isfile(path):
        # merge-multiple artifact downloads are FLAT (the zip root holds the
        # files without the source-folder prefix): fall back to the basename
        path = os.path.join(dirpath, os.path.basename(rel))
        if not os.path.isfile(path):
            return None, "no report (control failed?)"
    val = counter(path)
    if unit == "tests":
        tests, fails = val
        mark = " ❌" if fails else ""
        return val, f"{tests} tests, {fails} failed{mark}"
    return val, f"{val} {unit}"


def count_in_artifact_zip(zip_path, control):
    """Count for one control inside a (downloaded) baseline artifact zip."""
    _label, _art, rel, counter, unit = control
    try:
        with tempfile.TemporaryDirectory() as td:
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                # the artifact zips are flat: try the source-relative path
                # first, then the basename (zip root)
                key = rel if rel in names else (os.path.basename(rel) if os.path.basename(rel) in names else None)
                if key is None:
                    return None, "no report (control failed?)"
                target = os.path.join(td, key)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(zf.read(key))
            return count_in_dir(td, control)
    except Exception:
        return None, "no report (control failed?)"


def download_artifact(archive_url, dest):
    req = urllib.request.Request(archive_url, headers={"User-Agent": "devsecops-findings"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
        fh.write(resp.read())


def latest_successful_release_run():
    """The baseline: latest successful push run on the base branch."""
    _st, payload = api("GET", f"/repos/{REPO}/actions/runs?branch={BASE_BRANCH}&event=push&status=completed&per_page=30")
    runs = payload.get("workflow_runs", []) if isinstance(payload, dict) else payload
    for r in runs:
        # substring match: the workflow is named "devsecops pipeline"
        # (the repo's own gate ladder is named "devsecops-pipeline" - the
        # space is what disambiguates the two)
        if WORKFLOW_NAME in r.get("workflow_name", "") and r.get("conclusion") == "success":
            return r
    return None


def baseline_counts(baseline_run):
    """Counts for every control in the baseline run's report artifacts."""
    _st, payload = api("GET", f"/repos/{REPO}/actions/runs/{baseline_run['id']}/artifacts?per_page=100")
    arts = payload.get("artifacts", []) if isinstance(payload, dict) else payload
    out = {}
    for art in arts:
        name = art.get("name", "")
        control = next((c for c in CONTROLS if c[1] == name), None)
        if not control:
            continue
        tmp = os.path.join(tempfile.gettempdir(), f"baseline-{name}.zip")
        download_artifact(art["archive_download_url"], tmp)
        out[name] = count_in_artifact_zip(tmp, control)
        os.unlink(tmp)
    return out


# The develop controls the PR's gate verdict is evaluated over (this job's
# needs - the controls that run on a PR: the source controls + the bench
# unit-test suite).
GATE_CONTROLS = ["sast", "secrets", "secrets-th", "quality", "iac", "sca", "unit-tests"]


def gate_verdict():
    """(ok, failed) from this run's control results, or None if GATE_NEEDS
    is unset/unparseable (the section is simply omitted - never a guess)."""
    raw = os.environ.get("GATE_NEEDS", "")
    if not raw:
        return None
    try:
        needs = json.loads(raw)
    except (ValueError, TypeError):
        return None
    failed = [k for k in GATE_CONTROLS if (needs.get(k) or {}).get("result") != "success"]
    return (len(failed) == 0, failed)


def blocking_count(rel):
    """CRITICAL+HIGH count for one control report file.

    None = not applicable (no severity grading for this report, e.g. junit /
    ruff / gitleaks) or the report is missing / ungradeable.
    """
    for candidate in (os.path.join(REPORTS_DIR, rel), os.path.join(REPORTS_DIR, os.path.basename(rel))):
        if os.path.isfile(candidate):
            tool = gate_findings.TOOL_BY_FILE.get(os.path.basename(candidate))
            grader = gate_findings.GRADERS.get(tool) if tool else None
            if grader is None:
                return None
            try:
                c = grader(candidate)
                return c["CRITICAL"] + c["HIGH"]
            except Exception:
                return None
    return None


# detail width for the per-finding rows; shrunk automatically by main() if
# the rendered comment would exceed GitHub's 65535-char limit (all findings
# stay listed, only the detail text shortens)
DETAIL_LIMIT = 120


def findings_items():
    """Every individual finding in this run's PR reports (flat layout)."""
    items = []
    for fname in PR_REQUIRED_REPORTS:
        tool = gate_findings.TOOL_BY_FILE.get(fname)
        if tool is None:
            continue
        path = os.path.join(REPORTS_DIR, fname)
        if not os.path.isfile(path):
            continue
        try:
            items.extend(gate_findings.list_findings(path, tool, DETAIL_LIMIT))
        except Exception:
            continue
    return items


def render(pr_run, baseline):
    lines = [MARKER, "", "## DevSecOps findings — release pipeline (PR feedback)", ""]
    verdict = gate_verdict()
    if verdict is not None:
        ok, failed = verdict
        if ok:
            lines.append(
                "**Gate (tests + source controls):** ✅ PASS — every required control "
                "succeeded for this commit (the same fail-closed logic the G2 gate "
                "applies before a release)."
            )
        else:
            lines.append(
                f"**Gate (tests + source controls):** ❌ FAIL — not successful: "
                f"{', '.join('`' + k + '`' for k in failed)}. This run FAILS the PR "
                "check (fail-closed, enforced - the same logic the G2 gate applies "
                "before a release)."
            )
        lines.append("")
    if baseline:
        lines.append(
            f"Baseline: [release run #{baseline['id']}]({baseline['html_url']}) "
            f"on `{BASE_BRANCH}` ({baseline.get('created_at', '?')[:10]}) — the latest successful release run."
        )
    else:
        lines.append(f"Baseline: none — no successful release run on `{BASE_BRANCH}` yet (first-run counts).")
    lines += ["", "| Control | This run | vs baseline | C/H (reported) |", "|---|---|---|---|"]

    # this run's counts (artifacts merged flat into ./reports/)
    for label, art_name, _rel, _counter, unit in CONTROLS:
        val, display = count_in_dir(REPORTS_DIR, (label, art_name, _rel, _counter, unit))
        base = baseline_counts_global.get(art_name) if baseline else None
        if val is None:
            delta = "—"
        elif base is None or base[0] is None:
            delta = "new / no baseline"
        else:
            b = base[0]
            if unit == "tests":
                bt, bf = b
                if val[1] > 0:
                    delta = "❌ failing"
                elif bf > 0:
                    delta = f"fixed (baseline had {bf} failing)"
                else:
                    delta = f"= passing ({val[0]} tests)"
            elif val > b:
                delta = f"+{val - b} new ⚠️"
            elif val < b:
                delta = f"−{b - val} resolved"
            else:
                delta = f"= {val}"
        lines.append(f"| {label} | {display} | {delta} | {('n/a' if blocking_count(_rel) is None else blocking_count(_rel))} |")

    # the PR comment carries the blocking band only (CRITICAL/HIGH); the full
    # list (all severities) goes to the job Summary (written in main below).
    # This app is REPORT-ONLY for C/H (the comment shows them for review -
    # they never fail the check).
    items = findings_items()
    ch_items = [i for i in items if i[0] in ("CRITICAL", "HIGH")]
    lines += ["", "## CRITICAL/HIGH findings (this run — reported, not blocking)", ""]
    if ch_items:
        lines.append(gate_findings.render_findings_md(ch_items))
    else:
        lines.append("_no CRITICAL/HIGH findings in this run's reports_\n")
    lines += ["", "_The full list (every finding, all severities) is in this run's job **Summary** tab._", ""]

    lines += ["", f"Run: [#{pr_run['id']}]({pr_run['html_url']}) — the source controls scanned the PR merge ref.", ""]
    return "\n".join(lines)


baseline_counts_global = {}


def find_existing_comment():
    _st, comments = api("GET", f"/repos/{REPO}/issues/{PR}/comments?per_page=100")
    for c in comments:
        if MARKER in (c.get("body") or ""):
            return c
    return None


def main():
    global baseline_counts_global
    if not TOKEN or not REPO or not PR:
        sys.exit("GITHUB_TOKEN / GITHUB_REPOSITORY / PR_NUMBER not set")

    # this run's metadata (for the comment footer)
    pr_run = {
        "id": os.environ.get("GITHUB_RUN_ID", "n/a"),
        "html_url": os.environ.get("GITHUB_SERVER_URL", "https://github.com") + f"/{REPO}/actions/runs/{os.environ.get('GITHUB_RUN_ID', 'n/a')}",
    }

    baseline = latest_successful_release_run()
    if baseline:
        baseline_counts_global = baseline_counts(baseline)
        print(f"baseline: run {baseline['id']} on {BASE_BRANCH}")

    body = render(pr_run, baseline)
    if len(body) > 55000:  # GitHub comment limit is 65535 chars - keep a margin
        global DETAIL_LIMIT
        DETAIL_LIMIT = 40
        body = render(pr_run, baseline)
    existing = find_existing_comment()
    if existing:
        api("PATCH", f"/repos/{REPO}/issues/comments/{existing['id']}", {"body": body})
        print(f"updated existing findings comment {existing['id']}")
    else:
        api("POST", f"/repos/{REPO}/issues/{PR}/comments", {"body": body})
        print(f"posted new findings comment on PR {PR}")

    # the full findings list (all severities) goes to the job Summary tab -
    # the PR comment above carries CRITICAL/HIGH only; the rest stays visible
    # here (release runs have their own full-list step in the G2 job)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        with open(summary_path, "a") as fh:
            fh.write("## All findings (this run — full list, all severities)\n\n")
            fh.write(gate_findings.render_findings_md(findings_items()))
            fh.write("\n_The PR comment lists CRITICAL/HIGH only; the rest is here._\n")

    # ── PR findings gate (REPORT-ONLY for CRITICAL/HIGH): findings are
    #    graded + listed but never fail the check; the run FAILS when a
    #    required report is missing or ungradeable, or a graded control did
    #    not succeed. The comment is posted BEFORE the exit so the failure
    #    reason is always visible on the PR.
    raw = os.environ.get("GATE_NEEDS", "")
    needs = None
    if raw:
        try:
            needs = json.loads(raw)
        except ValueError:
            needs = None  # the comment section was omitted; the gate still grades the reports
    _rows, block = gate_findings.evaluate(REPORTS_DIR, PR_REQUIRED_REPORTS, needs, GATE_CONTROLS)
    if block:
        for b in block:
            print(f"::error::PR findings gate BLOCKED: {b}")
        sys.exit(1)
    print("PR findings gate: PASS - report-only for CRITICAL/HIGH findings; no missing/ungradeable reports, every graded control successful (the PR check stays green)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"::error::pr_findings.py failed: {e}", file=sys.stderr)
        sys.exit(1)
