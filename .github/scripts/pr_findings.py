#!/usr/bin/env python3
"""PR findings comment for the frappe-gates-demo release pipeline
(the facility360 devsecops standard, ported - one pipeline per app).

Reads THIS run's develop-phase report artifacts (downloaded flat to
./reports by the pr-comment job), renders ONE PR comment in the shared
reference format (the django-gates-demo findings comment: the gate
verdict line, the per-control table with C/H counts and the new-vs-main
delta, the new-C/H findings section, the fixed-findings block, the
baseline note and the run link), diffs the CRITICAL/HIGH band against the
baseline (the latest SUCCESSFUL release run on the base branch, fetched
via the GitHub API), and posts/updates one marker-anchored comment on the
PR. The same rendered body is delivered as the run's Summary (the run
page), where the full all-severity list follows.

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


def _opener() -> urllib.request.OpenerDirector:
    # ONLY the HTTP(S) handlers (urlopen would also install file://, ftp://
    # and data: handlers - a dynamic URL must not be able to read local
    # files). The same pattern as hermes_review.py / defectdojo_upload.py.
    opener = urllib.request.OpenerDirector()
    for h in (urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPDefaultErrorHandler(),
              urllib.request.HTTPErrorProcessor(), urllib.request.HTTPRedirectHandler(), urllib.request.UnknownHandler()):
        opener.add_handler(h)
    return opener


_HTTP = _opener()

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
# and the bench suite are in the checkout), so checkov.sarif + junit.xml are
# required here. The image-scan report (trivy.sarif) is NOT required: the
# image scan is release-only (no image is built on a PR), so the file is
# simply absent on PR runs and the image-scan row is not rendered.
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
        with _HTTP.open(req, timeout=60) as resp:
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
    ("Image scan (trivy, built image)", "report-image-scan", "trivy.sarif", count_sarif, "vulnerabilities"),
    ("Unit tests (bench suite, real MariaDB)", "report-unit-tests", "unit-tests/junit.xml", count_junit, "tests"),
]

# The AI review (the ai-security job's report: verdict.json + ai-review.sarif
# in the report-ai-review artifact). It is advisory (NOT in the gate
# controls, like hmis's ai_security) but gets a table row.
AI_REVIEW_LABEL = "AI review (Hermes, PR)"
AI_REVIEW_ART = "report-ai-review"
AI_REVIEW_SARIF = "ai-review.sarif"


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


def download_artifact(archive_url, dest):
    req = urllib.request.Request(archive_url, headers={"User-Agent": "devsecops-findings"})
    with _HTTP.open(req, timeout=120) as resp, open(dest, "wb") as fh:
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


# The CRITICAL/HIGH band for the comment (the report-only blocking band).
# "ERROR" is trivy's SARIF level for both Critical and High - normalized to
# HIGH by the gate_findings grader, which never emits "ERROR" as a band.
CH_BAND = ("CRITICAL", "HIGH")


def _md_cell(s, limit):
    """Markdown-table-safe cell text (whitespace collapsed, pipes escaped)."""
    s = str(s).replace("\n", " ").replace("|", "\\|").strip()
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def _finding_key(label, rule, loc, detail=""):
    """Identity across runs (the reference findings.py key): same control,
    rule and file - line numbers are NOT part of it (lines move when code
    is edited above a finding). The AI review is the exception: its SARIF
    rule id encodes only the severity, so different findings in the same
    file+band would collapse - its key carries the location and the message
    (the advisory line accepts the extra churn)."""
    if label == AI_REVIEW_LABEL:
        return f"{label}|{rule}|{loc}|{str(detail)[:60]}"
    filepart = loc.rsplit(":", 1)[0] if ":" in loc else loc
    return f"{label}|{rule}|{filepart}"


def _ch_items(label, path, tool):
    """Every C/H-band finding in one report file as (display-item, key).
    display-item normalizes the severity to CRITICAL/HIGH."""
    out = []
    try:
        items = gate_findings.list_findings(path, tool, DETAIL_LIMIT)
    except Exception:
        return out
    for sev, toolx, rule, loc, detail in items:
        if sev not in CH_BAND:
            continue
        out.append(((sev, toolx, rule, loc, detail), _finding_key(label, rule, loc, detail)))
    return out


def _ai_review_from_dir(dirpath):
    """(verdict-dict-or-None, ch-items) for the hermes review report in a
    (flat) reports dir: verdict.json (control "ai-review") + ai-review.sarif."""
    verdict = None
    vpath = os.path.join(dirpath, "verdict.json")
    if os.path.isfile(vpath):
        try:
            with open(vpath) as fh:
                d = json.load(fh)
            if isinstance(d, dict) and d.get("control") == "ai-review":
                verdict = d
        except (ValueError, OSError):
            verdict = None
    ch = []
    spath = os.path.join(dirpath, AI_REVIEW_SARIF)
    if os.path.isfile(spath):
        # a standard SARIF - the trivy parser reads level/ruleId/location
        ch = _ch_items(AI_REVIEW_LABEL, spath, "trivy")
    return verdict, ch


def baseline_data(baseline_run):
    """Per-control baseline from the baseline run's report artifacts:
    {artifact name: {"label", "count", "display", "ch": [(item, key), ...]}}.
    The findings list (not just the count) is what the new-vs-main diff
    compares (same rule + file, line numbers ignored)."""
    _st, payload = api("GET", f"/repos/{REPO}/actions/runs/{baseline_run['id']}/artifacts?per_page=100")
    arts = payload.get("artifacts", []) if isinstance(payload, dict) else payload
    out = {}
    for art in arts:
        name = art.get("name", "")
        tmp = os.path.join(tempfile.gettempdir(), f"baseline-{name}.zip")
        try:
            download_artifact(art["archive_download_url"], tmp)
            with tempfile.TemporaryDirectory() as td:
                with zipfile.ZipFile(tmp) as zf:
                    zf.extractall(td)
                if name == AI_REVIEW_ART:
                    verdict, ch = _ai_review_from_dir(td)
                    if verdict is None and not ch:
                        continue
                    out[name] = {
                        "label": AI_REVIEW_LABEL,
                        "count": len(ch),
                        "display": (verdict.get("detail") or "")[:140] if verdict else "no report (control failed?)",
                        "ch": ch,
                    }
                    continue
                control = next((c for c in CONTROLS if c[1] == name), None)
                if not control:
                    continue
                val, display = count_in_dir(td, control)
                ch = []
                fname = os.path.basename(control[2])
                fpath = os.path.join(td, fname)
                if os.path.isfile(fpath):
                    tool = gate_findings.TOOL_BY_FILE.get(fname)
                    if tool:
                        ch = _ch_items(control[0], fpath, tool)
                out[name] = {"label": control[0], "count": val, "display": display, "ch": ch}
        except Exception:
            continue  # an unreadable baseline artifact is skipped, not fatal
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return out


# The develop controls the PR's gate verdict is evaluated over (this job's
# needs - the controls that run on a PR: the source controls + the bench
# unit-test suite). The image scan is release-only (no image is built on a
# PR), so it is not a gate input here. The AI review is deliberately NOT
# here either: like hmis's ai_security it is an advisory control, not a
# gate input.
GATE_CONTROLS = ["sast", "secrets", "secrets-th", "quality", "iac", "sca", "unit-tests"]


def _needs_map():
    raw = os.environ.get("GATE_NEEDS", "")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def gate_verdict():
    """(ok, failed) from this run's control results, or None if GATE_NEEDS
    is unset/unparseable (the section is simply omitted - never a guess)."""
    needs = _needs_map()
    if needs is None:
        return None
    failed = [k for k in GATE_CONTROLS if (needs.get(k) or {}).get("result") != "success"]
    return (len(failed) == 0, failed)


def _job_icon(needs, job, val):
    res = (needs.get(job) or {}).get("result") if needs else None
    if res is None:
        return "❌" if val is None else "✅"
    return {"success": "✅", "skipped": "⏭️"}.get(res, "❌")


def blocking_count(rel):
    """CRITICAL+HIGH count for one control report file.

    None = not applicable (no severity grading for this report, e.g. junit /
    gitleaks) or the report is missing / ungradeable.
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
    """Every individual finding in this run's PR reports (flat layout), as
    (control label, (severity, tool, rule, location, detail))."""
    label_by_file = {os.path.basename(c[2]): c[0] for c in CONTROLS}
    label_by_file[AI_REVIEW_SARIF] = AI_REVIEW_LABEL
    items = []
    for fname in PR_REQUIRED_REPORTS + [AI_REVIEW_SARIF]:
        tool = gate_findings.TOOL_BY_FILE.get(fname)
        if tool is None:
            tool = "trivy" if fname == AI_REVIEW_SARIF else None
        if tool is None:
            continue
        path = os.path.join(REPORTS_DIR, fname)
        if not os.path.isfile(path):
            continue
        try:
            for it in gate_findings.list_findings(path, tool, DETAIL_LIMIT):
                items.append((label_by_file.get(fname, fname), it))
        except Exception:
            continue
    return items


def render(pr_run, baseline, bdata):
    sha = os.environ.get("HEAD_SHA") or os.environ.get("GITHUB_SHA", "")
    lines = [MARKER, "", f"## DevSecOps findings for {sha[:7]}", ""]
    verdict = gate_verdict()
    if verdict is not None:
        ok, failed = verdict
        if ok:
            lines.append(
                "✅ **PR gate** pass — every required control succeeded for this commit "
                "(tests + source controls; the release G2 gate re-checks the same controls "
                "before a release)"
            )
        else:
            lines.append(
                f"❌ **PR gate** fail — not successful: "
                f"{', '.join('`' + k + '`' for k in failed)} (fail-closed - this run FAILS the "
                "PR check; the same logic the G2 gate applies before a release)"
            )
        lines.append("")
    lines += ["| | Control | C/H (reported) | New vs main | Detail |", "|---|---|---|---|---|"]

    needs = _needs_map()
    all_items = findings_items()
    # this run's C/H identity keys per control label
    cur_keys = {}
    cur_ch = []
    for label, it in all_items:
        if it[0] in CH_BAND:
            cur_ch.append((label, it))
            cur_keys.setdefault(label, set()).add(_finding_key(label, it[2], it[3], it[4]))

    # this run's counts (artifacts merged flat into ./reports/)
    for label, art, _rel, _counter, unit in CONTROLS:
        val, display = count_in_dir(REPORTS_DIR, (label, art, _rel, _counter, unit))
        # the image-scan control is release-only (no image is built on a PR
        # run): a missing report is the expected state, so its row is
        # simply not rendered (unlike a missing REQUIRED control report,
        # which is a red flag that must be shown)
        if val is None and art == "report-image-scan":
            continue
        chn = blocking_count(_rel)
        base = bdata.get(art) if bdata else None
        if base is None or unit == "tests":
            newcol = "–"  # no baseline for this control / no finding identity (test counts)
        else:
            base_keys = {k for _i, k in base.get("ch", [])}
            newcol = str(len(cur_keys.get(label, set()) - base_keys))
        icon = _job_icon(needs, art.removeprefix("report-"), val)
        lines.append(f"| {icon} | {label} | {chn if chn is not None else '–'} | {newcol} | {_md_cell(display, 140)} |")

    # the AI review row (advisory control - the hermes client's verdict)
    ai_verdict, ai_ch = _ai_review_from_dir(REPORTS_DIR)
    ai_base = bdata.get(AI_REVIEW_ART) if bdata else None
    if ai_verdict is not None:
        icon = {"pass": "✅", "fail": "❌", "skipped": "⏭️"}.get(ai_verdict.get("status"), "❔")
        chn = str(len(ai_ch))
        newcol = str(len({k for _i, k in ai_ch} - {k for _i, k in ai_base.get("ch", [])})) if ai_base else "–"
        lines.append(f"| {icon} | {AI_REVIEW_LABEL} | {chn} | {newcol} | {_md_cell(ai_verdict.get('detail') or '', 140)} |")
    else:
        res = (needs.get("ai-security") or {}).get("result") if needs else None
        if res in (None, "skipped"):
            icon, why = "⏭️", "job skipped (or its result is not visible)"
        elif res == "success":
            icon, why = "⚠️", "job succeeded but no report landed"
        else:
            icon, why = "❌", "job failed before the verdict"
        lines.append(f"| {icon} | {AI_REVIEW_LABEL} | – | – | no report ({why}) |")

    # the new-vs-main C/H section (the reference format's "new blocking"
    # section; the C/H band is this app's reported band). Like the
    # reference, a control with no baseline entry is "unknown", not
    # "all new" - its findings are shown in the table only.
    base_keys_all = set()
    compared_labels = set()
    for d in bdata.values():
        base_keys_all |= {k for _i, k in d.get("ch", [])}
        compared_labels.add(d.get("label"))
    if bdata:
        new_items = [
            (l, it) for l, it in cur_ch
            if l in compared_labels and _finding_key(l, it[2], it[3], it[4]) not in base_keys_all
        ]
        carried = sum(
            1 for l, it in cur_ch
            if l in compared_labels and _finding_key(l, it[2], it[3], it[4]) in base_keys_all
        )
        lines += ["", f"### New C/H findings in this PR ({len(new_items)})", ""]
        if new_items:
            _ch_table(lines, new_items)
        else:
            lines.append("_no new C/H findings vs the baseline_")
            if carried:
                lines.append(f"_{carried} C/H finding(s) carried over from main - the full list is in the job summary._")
    else:
        lines += ["", f"### C/H findings in this PR ({len(cur_ch)}) — first run, no baseline to compare", ""]
        if cur_ch:
            _ch_table(lines, cur_ch)
        else:
            lines.append("_no CRITICAL/HIGH findings in this run's reports_")

    # fixed findings (baseline C/H identities absent from this run) - only
    # for controls present in this run (a missing report means the control
    # did not run - its baseline findings are neither new nor fixed)
    cur_keys_all = {k for ks in cur_keys.values() for k in ks}
    fixed = []
    for art, d in bdata.items():
        label = d.get("label")
        if art == AI_REVIEW_ART:
            present = any(
                os.path.isfile(os.path.join(REPORTS_DIR, f)) for f in ("verdict.json", AI_REVIEW_SARIF)
            )
        else:
            control = next((c for c in CONTROLS if c[1] == art), None)
            present = bool(control) and any(
                os.path.isfile(os.path.join(REPORTS_DIR, p))
                for p in (control[2], os.path.basename(control[2]))
            )
        if not present:
            continue
        cur = cur_keys.get(label, set())
        fixed += sorted(k for _i, k in d.get("ch", []) if k not in cur)
    fixed = sorted(set(fixed))
    if fixed:
        lines += ["", f"<details><summary>Fixed compared with main ({len(fixed)})</summary>", ""]
        lines += [f"- `{_md_cell(k, 150)}`" for k in fixed[:50]] + ["", "</details>"]

    if bdata:
        lines += ["", f"_New vs main_ compares with the latest successful release run on `{BASE_BRANCH}` "
                     f"([run #{baseline['id']}]({baseline['html_url']}), {baseline.get('created_at', '?')[:10]}): "
                     "the same finding means the same control, rule and file (line numbers ignored). "
                     "– means main has no findings to compare with for that control._"]
    else:
        lines += ["", f"_No successful release run on `{BASE_BRANCH}` with comparable reports yet, "
                     "so nothing is marked new._"]
    lines += ["", f"Full tables (every finding, all severities) are in each job's **Summary**: "
                  f"[run {pr_run['id']}]({pr_run['html_url']}) — the source controls scanned the PR merge ref. "
                  "Updated in place on every run."]
    return "\n".join(lines)


def _ch_table(lines, items):
    lines += ["| Control | Severity | Finding | Where | Detail |", "|---|---|---|---|---|"]
    for label, (sev, _tool, rule, loc, detail) in items[:30]:
        lines.append(f"| {_md_cell(label, 40)} | {sev} | `{_md_cell(rule, 60)}` | `{_md_cell(loc, 80)}` | {_md_cell(detail, DETAIL_LIMIT)} |")
    if len(items) > 30:
        lines.append(f"\n…and {len(items) - 30} more: see the job summaries.")


baseline_counts_global = {}


def find_existing_comment():
    _st, comments = api("GET", f"/repos/{REPO}/issues/{PR}/comments?per_page=100")
    for c in comments:
        if MARKER in (c.get("body") or ""):
            return c
    return None


def main():
    global DETAIL_LIMIT
    if not TOKEN or not REPO or not PR:
        sys.exit("GITHUB_TOKEN / GITHUB_REPOSITORY / PR_NUMBER not set")

    # this run's metadata (for the comment footer)
    pr_run = {
        "id": os.environ.get("GITHUB_RUN_ID", "n/a"),
        "html_url": os.environ.get("GITHUB_SERVER_URL", "https://github.com") + f"/{REPO}/actions/runs/{os.environ.get('GITHUB_RUN_ID', 'n/a')}",
    }

    baseline = latest_successful_release_run()
    bdata = baseline_data(baseline) if baseline else {}
    if baseline:
        print(f"baseline: run {baseline['id']} on {BASE_BRANCH}")

    body = render(pr_run, baseline, bdata)
    if len(body) > 55000:  # GitHub comment limit is 65535 chars - keep a margin
        DETAIL_LIMIT = 40
        body = render(pr_run, baseline, bdata)
    existing = find_existing_comment()
    if existing:
        api("PATCH", f"/repos/{REPO}/issues/comments/{existing['id']}", {"body": body})
        print(f"updated existing findings comment {existing['id']}")
    else:
        api("POST", f"/repos/{REPO}/issues/{PR}/comments", {"body": body})
        print(f"posted new findings comment on PR {PR}")

    # the run's Summary gets the SAME rendered body (the reference format -
    # the run page delivers the summary like the reference run), and under
    # it the full all-severity list (the PR comment carries C/H only).
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        all_items = findings_items()
        with open(summary_path, "a") as fh:
            fh.write(body)
            fh.write("\n\n## All findings (this run — full list, all severities)\n\n")
            fh.write(gate_findings.render_findings_md([it for _l, it in all_items]))
            fh.write("\n_The PR comment lists C/H only (new vs main); the full list is here._\n")

    # ── PR findings gate (REPORT-ONLY for CRITICAL/HIGH): findings are
    #    graded + listed but never fail the check; the run FAILS when a
    #    required report is missing or ungradeable, or a graded control did
    #    not succeed. The comment is posted BEFORE the exit so the failure
    #    reason is always visible on the PR.
    needs = _needs_map()
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
