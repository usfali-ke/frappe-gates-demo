#!/usr/bin/env python3
"""CRITICAL/HIGH findings gate for the frappe-gates-demo release pipeline
(the facility360 standard, ported: same canonical severity grading).

Canonical severity grading shared by:
  - the G2 control gate (release runs - the "Findings gate" step of
    gate-g2, report-only for findings: CRITICAL/HIGH findings are graded
    and reported, never block; a missing/ungradeable required report or a
    failed graded control blocks - no tag, no webhook)
  - the PR findings comment (findings.py imports this module - the PR run
    posts the comment with the same counts, then fails its check only on a
    missing/ungradeable report or a failed graded control)

Severity rules (tool-native severity; findings are graded and REPORTED -
report-only policy 2026-10-28, extended to facility360 2026-10-29;
fail-closed on a report that cannot be graded):
  semgrep (semgrep.json)          extra.severity == "ERROR"  -> HIGH (reported;
                                semgrep's ERROR band is its high-severity
                                band) - WARNING -> reported,
                                INFO -> reported
  gitleaks (gitleaks.json)        no tool severity: every hit is reported
                                (review bucket) - verified-leak detection is
                                trufflehog's job in this pipeline (gitleaks
                                pattern hits are mostly false positives)
  trufflehog (thufflehog.json, NDJSON)
                                Verified == true -> CRITICAL (reported - a
                                live-verified credential); unverified ->
                                reported
  trivy fs / image (*trivy*.sarif) results[].level in {HIGH, CRITICAL}
                                -> reported (the scans run with
                                --severity HIGH,CRITICAL, so any result is
                                already high/critical)
  checkov (checkov.sarif)         results[].level == "error" -> HIGH
                                (reported; checkov maps rule severity
                                CRITICAL/HIGH -> error, MEDIUM/LOW -> warning)
  ruff (ruff.json)               quality control (ruff, repo config): rule
                                code band - F (Pyflakes: real bugs) and B
                                (Bugbear) -> HIGH, E/W (style/warnings)
                                -> MEDIUM, I/UP/RUF (import/upgrade/
                                ruff-specific) -> LOW. The control job fails
                                only when ruff cannot run/produce its report
                                (fail-closed control health); the findings
                                are graded here (reported)
  junit (junit.xml)               the bench unit-test suite: failed
                                tests -> reported (count only, no severity
                                concept) - the control job already FAILS on
                                any failure

What BLOCKS: a required report that is missing or ungradeable, or a graded
control result that is not successful. CRITICAL/HIGH findings never block -
they are surfaced in the gate table / PR comment for review, and EVERY
individual finding is listed (list_findings / render_findings_md) in the G2
step summary and the PR comment - counts alone are not enough to act on.

Exit codes (CLI): 0 = nothing blocks, 1 = BLOCK (a required report missing
or ungradeable, or a graded control result not successful), 2 = usage error.
"""

import argparse
import json
import os
import sys

# defusedxml: no DTD/external-entity handling (semgrep use-defused-xml-parse)
from defusedxml import ElementTree as ET

# report file (as stored in the reports dir - the artifact zips are flat, so
# basenames) -> grading tool
TOOL_BY_FILE = {
    "semgrep.json": "semgrep",
    "gitleaks.json": "gitleaks",
    # NOTE: "thufflehog.json" (not trufflehog.json) is the real report name -
    # the workflow's trufflehog-scan call writes that file (line in the
    # secrets-th job); keep the key in sync with the workflow.
    "thufflehog.json": "trufflehog",
    "trivy-fs.sarif": "trivy",
    "trivy.sarif": "trivy",
    "checkov.sarif": "checkov",
    "ruff.json": "ruff",
    "junit.xml": "junit",
}


def _load_json(path):
    with open(path) as fh:
        return json.load(fh)


def grade_semgrep(path):
    """semgrep JSON: per-result extra.severity (INFO/WARNING/ERROR)."""
    d = _load_json(path)
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in d.get("results", []):
        sev = (r.get("extra") or {}).get("severity", "")
        if sev == "ERROR":
            c["HIGH"] += 1
        elif sev == "WARNING":
            c["MEDIUM"] += 1
        else:
            c["LOW"] += 1
    return c


def grade_gitleaks(path):
    """gitleaks JSON: no severity - reported, never blocking (see module doc)."""
    d = _load_json(path)
    hits = d if isinstance(d, list) else d.get("Leaks", d.get("findings", []))
    return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": len(hits), "LOW": 0}


def grade_thufflehog(path):
    """trufflehog NDJSON: Verified == true -> CRITICAL (a live credential)."""
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                c["LOW"] += 1
                continue
            if d.get("Verified") is True:
                c["CRITICAL"] += 1
            else:
                c["MEDIUM"] += 1
    return c


def _sarif_levels(path):
    d = _load_json(path)
    out = []
    for run in d.get("runs", []):
        for r in run.get("results", []):
            out.append((r.get("level") or "").upper())
    return out


def grade_trivy(path):
    """trivy SARIF: results[].level (the scans run --severity HIGH,CRITICAL)."""
    levels = _sarif_levels(path)
    return {
        "CRITICAL": levels.count("CRITICAL"),
        "HIGH": levels.count("HIGH"),
        "MEDIUM": levels.count("MEDIUM"),
        "LOW": len(levels) - levels.count("CRITICAL") - levels.count("HIGH")
        - levels.count("MEDIUM"),
    }


def grade_checkov(path):
    """checkov SARIF: CRITICAL/HIGH rules land as level=error."""
    levels = _sarif_levels(path)
    return {
        "CRITICAL": 0,
        "HIGH": levels.count("ERROR"),
        "MEDIUM": levels.count("WARNING"),
        "LOW": len(levels) - levels.count("ERROR") - levels.count("WARNING"),
    }


def grade_typecheck(path):
    """typecheck: quality control (tsc diagnostics) - count only, no severity."""
    d = _load_json(path)
    n = len(d) if isinstance(d, list) else len(d.get("results", []))
    return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": n}


def grade_ruff(path):
    """ruff JSON: rule-code banding (see module doc): F/B -> HIGH,
    E/W -> MEDIUM, everything else (I/UP/RUF) -> LOW."""
    d = _load_json(path)
    items = d if isinstance(d, list) else d.get("results", [])
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for i in items:
        code = str(i.get("code", ""))
        if code.startswith(("F", "B")):
            c["HIGH"] += 1
        elif code.startswith(("E", "W")):
            c["MEDIUM"] += 1
        else:
            c["LOW"] += 1
    return c


def _junit_suites(path):
    tree = ET.parse(path)
    root = tree.getroot()
    return [root] if root.tag == "testsuite" else root.findall(".//testsuite")


def _junit_failing_testcases(path):
    """The failing/erroring testcases: (classname, name, failure-message)."""
    out = []
    for s in _junit_suites(path):
        for tc in s.findall("testcase"):
            for f in list(tc.findall("failure")) + list(tc.findall("error")):
                msg = (f.get("message") or (f.text or "")).strip()
                out.append((tc.get("classname", "?"), tc.get("name", "?"), msg))
    return out


def grade_junit(path):
    """junit: the e2e suite - failed tests count only (no severity concept)."""
    fails = 0
    for s in _junit_suites(path):
        fails += int(s.get("failures", 0) or 0) + int(s.get("errors", 0) or 0)
    return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": fails}


GRADERS = {
    "semgrep": grade_semgrep,
    "gitleaks": grade_gitleaks,
    "trufflehog": grade_thufflehog,
    "trivy": grade_trivy,
    "checkov": grade_checkov,
    "typecheck": grade_typecheck,
    "ruff": grade_ruff,
    "junit": grade_junit,
}


def _md_cell(s, limit):
    """Markdown-table-safe cell text (whitespace collapsed, pipes escaped)."""
    s = str(s).replace("\n", " ").replace("|", "\\|").strip()
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return s


def list_findings(path, tool, detail_limit=120):
    """Every individual finding in one report file.

    Returns a list of (severity, tool, rule, location, detail); severity is
    CRITICAL/HIGH/MEDIUM/LOW ("" for tools without a severity concept -
    gitleaks/typecheck/junit). Used by the G2 summary and the PR comment to
    list ALL findings, not just the counts.
    """
    out = []
    if tool == "semgrep":
        d = _load_json(path)
        for r in d.get("results", []):
            extra = r.get("extra") or {}
            sev = extra.get("severity", "")
            band = {"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(sev, "LOW")
            loc = "%s:%s" % (r.get("path", "?"), (r.get("start") or {}).get("line", "?"))
            out.append((band, tool, r.get("check_id", "?"), loc, extra.get("message", "")))
    elif tool == "gitleaks":
        d = _load_json(path)
        hits = d if isinstance(d, list) else d.get("Leaks", d.get("findings", []))
        for h in hits:
            loc = "%s:%s" % (h.get("File", "?"), h.get("StartLine", "?"))
            out.append(("", tool, h.get("RuleID", "?"), loc, h.get("Description", "")))
    elif tool == "trufflehog":
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                loc_obj = d.get("Location") or {}
                loc = "%s:%s" % (loc_obj.get("Path", "?"), loc_obj.get("Line", "?"))
                sev = "CRITICAL" if d.get("Verified") is True else "MEDIUM"
                out.append((sev, tool, d.get("DetectorName", "?"), loc, d.get("Description", "")))
    elif tool in ("trivy", "checkov"):
        d = _load_json(path)
        for run in d.get("runs", []):
            for r in run.get("results", []):
                lvl = (r.get("level") or "").upper()
                if tool == "checkov":
                    band = {"ERROR": "HIGH", "WARNING": "MEDIUM"}.get(lvl, "LOW")
                else:
                    band = lvl if lvl in ("CRITICAL", "HIGH") else (lvl or "LOW")
                phys = (((r.get("locations") or [{}])[0]).get("physicalLocation") or {})
                art = phys.get("artifactLocation") or {}
                region = phys.get("region") or {}
                loc = "%s:%s" % (art.get("uri", "?"), region.get("startLine", "?"))
                rule = r.get("ruleId") or (r.get("rule") or {}).get("id", "?")
                msg = ((r.get("message")) or {}).get("text", "")
                out.append((band, tool, rule, loc, msg))
    elif tool == "typecheck":
        d = _load_json(path)
        items = d if isinstance(d, list) else d.get("results", [])
        for item in items:
            loc = "%s:%s" % (item.get("file", "?"), item.get("line", "?"))
            code = item.get("code", "?")
            msg = item.get("message", "")
            out.append(("", tool, code, loc, msg))
    elif tool == "ruff":
        d = _load_json(path)
        items = d if isinstance(d, list) else d.get("results", [])
        for item in items:
            code = str(item.get("code", ""))
            band = "HIGH" if code.startswith(("F", "B")) else (
                "MEDIUM" if code.startswith(("E", "W")) else "LOW")
            loc_obj = item.get("location") or {}
            line = loc_obj.get("row", loc_obj.get("line", "?"))
            loc = "%s:%s" % (item.get("filename", "?"), line)
            out.append((band, tool, code, loc, item.get("message", "")))
    elif tool == "junit":
        # only the failing testcases are findings (passing tests are not)
        for cls, name, msg in _junit_failing_testcases(path):
            out.append(("", tool, name, cls, msg))
    return [
        (s, t, _md_cell(ru, 60), _md_cell(lo, 80), _md_cell(dt, detail_limit))
        for s, t, ru, lo, dt in out
    ]


def render_findings_md(items, detail_limit=120):
    """ALL individual findings as one markdown table (the summary/PR body)."""
    if not items:
        return "_no findings in the graded reports_\n"
    lines = ["| Severity | Tool | Rule | Location | Detail |", "|---|---|---|---|---|"]
    for sev, tool, rule, loc, detail in items:
        lines.append("| %s | %s | %s | %s | %s |" % (sev or "—", tool, "`" + rule + "`", "`" + loc + "`", detail))
    return "\n".join(lines) + "\n"


def evaluate(reports_dir, required_files, gate_needs=None, gate_controls=None):
    """Grade the required reports in reports_dir (flat layout, basenames).

    Returns (rows, block_reasons):
      rows         - list of (tool, file, crit, high, medium, low, status)
      block_reasons- list of human-readable reasons the gate must BLOCK
                       (a required report missing or ungradeable, or a graded
                       control not successful; CRITICAL/HIGH findings are
                       graded and reported in `rows` but never block)
    Fail-closed: a required report that is missing or unparseable blocks.
    """
    rows = []
    block = []
    for fname in required_files:
        tool = TOOL_BY_FILE.get(fname, fname.rsplit(".", 1)[0])
        path = os.path.join(reports_dir, fname)
        if not os.path.isfile(path):
            rows.append((tool, fname, None, None, None, None, "MISSING"))
            block.append(
                "required report %s is missing (a control report that did not "
                "land cannot be graded - fail-closed)" % fname
            )
            continue
        grader = GRADERS.get(tool)
        if grader is None:
            rows.append((tool, fname, None, None, None, None, "UNGRADED"))
            continue
        try:
            c = grader(path)
        except Exception as e:  # noqa: BLE001 - a report the gate cannot read must block
            rows.append((tool, fname, None, None, None, None, "PARSE ERROR"))
            block.append("report %s could not be graded (fail-closed): %s" % (fname, e))
            continue
        rows.append((tool, fname, c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], "ok"))
    if gate_needs is not None and gate_controls:
        failed = [
            k
            for k in gate_controls
            if (gate_needs.get(k) or {}).get("result") != "success"
        ]
        if failed:
            block.append(
                "graded control(s) not successful: " + ", ".join(failed)
            )
    return rows, block


def print_report(rows, block):
    print("| Control report | CRITICAL | HIGH | reported (review) | status |")
    print("|---|---|---|---|---|")
    for tool, fname, crit, high, med, low, status in rows:
        if status != "ok":
            print("| %s (%s) | - | - | - | %s |" % (tool, fname, status))
        else:
            print("| %s (%s) | %d | %d | %d | %s |" % (tool, fname, crit, high, (med or 0) + (low or 0), status))
    if block:
        print("")
        print("GATE VERDICT: BLOCK")
        for b in block:
            print("  - %s" % b)
    else:
        print("")
        print("GATE VERDICT: PASS (CRITICAL/HIGH findings, if any, are reported "
              "above - report-only policy; a missing/ungradeable report or a "
              "failed graded control would block)")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1].strip() if __doc__ else "findings gate")
    p.add_argument("--reports-dir", required=True, help="dir with the (flat) control reports")
    p.add_argument("--required", action="append", default=[], metavar="FILE",
                   help="report basename that MUST be gradeable (repeatable)")
    p.add_argument("--gate-needs", default="", help="JSON map of needs (job -> {result}) - optional")
    p.add_argument("--gate-controls", default="", help="comma list of graded job keys - with --gate-needs")
    p.add_argument("--findings-md", default="", metavar="FILE",
                   help="write the full per-finding list (all graded reports) to FILE as markdown")
    p.add_argument("--detail-limit", type=int, default=120,
                   help="max characters per finding detail (default 120)")
    a = p.parse_args(argv)

    gate_needs = None
    if a.gate_needs:
        try:
            gate_needs = json.loads(a.gate_needs)
        except ValueError:
            print("::error::--gate-needs is not valid JSON (fail-closed)")
            return 2
    gate_controls = [c.strip() for c in a.gate_controls.split(",") if c.strip()] or None

    rows, block = evaluate(a.reports_dir, a.required, gate_needs, gate_controls)
    print_report(rows, block)

    if a.findings_md:
        items = []
        for tool, fname, _c, _h, _m, _l, status in rows:
            if status != "ok":
                continue
            path = os.path.join(a.reports_dir, fname)
            try:
                items.extend(list_findings(path, tool, a.detail_limit))
            except Exception as e:  # noqa: BLE001 - report is already graded above
                print("::warning::could not list findings for %s: %s" % (fname, e))
        with open(a.findings_md, "w") as fh:
            fh.write(render_findings_md(items))
        print("findings detail written to %s (%d finding(s))" % (a.findings_md, len(items)))

    for b in block:
        print("::error::findings gate: %s" % b)
    return 1 if block else 0


if __name__ == "__main__":
    sys.exit(main())
