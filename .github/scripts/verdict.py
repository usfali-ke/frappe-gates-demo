"""One verdict per control.

Reads a tool's report, applies the threshold, writes `<output>=<json>`
({status, detail, tool, metrics, accepted}) to $GITHUB_OUTPUT for the gate
and evidence jobs, copies it to $VERDICT_FILE (inside the control's report
artifact, so each artifact is self-describing), and exits 1 on fail so the
control's own job goes red:

    python3 .github/scripts/verdict.py <check> [args...]

A report that is missing or unreadable is a fail — a scanner that didn't
run is not a clean scan. Tools always run with "don't fail on findings"
(their exit codes mean different things: findings vs. crashed), so this
script is the one place a threshold is decided. Settings come from env,
never from ${{ }} inside a script.

Accepted risks (security/accepted-risks.json) are applied here and listed
in the verdict (id, match, reason, expiry), so the evidence says what was
accepted and why; an expired entry no longer applies, and an
`"unfixed_only": true` entry stops applying once a fix is released.

Each parser also records its findings in one shape (`found`), which
findings.py turns into findings.json, SARIF, the job summary and
annotations, so a failed control says exactly what to fix. Outside Actions
(`make <control>`) GITHUB_OUTPUT may be unset and the findings print.
"""

import datetime as dt
import glob
import json
import os
import re
import sys
import tomllib

# The only XML parsed here is JUnit/coverage output from this job's own
# pytest run. The runner's Python links expat >= 2.4.1, so ElementTree
# resolves no external entities and refuses entity-expansion bombs — the
# risks semgrep's use-defused-xml-parse rule is about.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

import findings

env = os.environ.get
CONTROL = env("CONTROL", "")
# The control whose accepted-risk entries apply: another run of the same
# scan (e.g. the release's dependency re-check of image-scan's image)
# takes the same exceptions, not a register of its own.
RISK_CONTROL = env("RISK_CONTROL") or CONTROL
_applied = []
_findings = []
_state = {"kind": None}


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def load_jsonl(path):
    try:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]
    except (OSError, ValueError):
        return None


def missing(tool):
    tool_broke()
    return False, f"{tool} did not produce a report", None


def tool_broke():
    """The failure is the tool's (no usable output), not the code's."""
    _state["kind"] = "tool"


def found(severity, finding_id, title="", *, blocking, accepted=None, **where):
    """Record one finding. severity: critical/high/medium/low/info, or
    unknown (unrated, which is not low). where: file, line, package,
    version, where (free text), fix, url. Never a secret's value."""
    severity = (severity or "unknown").lower()
    _findings.append({
        "status": "accepted" if accepted else "blocking" if blocking else "reported",
        "severity": severity if severity in findings.SEVERITIES else "unknown",
        "id": str(finding_id), "title": title or "",
        **{k: v for k, v in where.items() if v not in (None, "")},
        **({"accepted": {k: accepted[k] for k in ("reason", "expires") if k in accepted}} if accepted else {}),
    })


def first_line(text, limit=200):
    return (str(text or "").strip().splitlines() or [""])[0][:limit]


def accepted(finding_id, text="", fixed=False, record=True):
    """The register entry if it accepts this finding for this control (and
    the entry hasn't expired, and isn't `unfixed_only` for a finding that
    now has a fix), else None. Records every entry used (record=False
    only looks)."""
    register = load(env("ACCEPTED_RISKS", "security/accepted-risks.json")) or {}
    today = dt.date.today().isoformat()
    for entry in register.get("accepted", []):
        if entry.get("control") != RISK_CONTROL or entry.get("id") != finding_id:
            continue
        if entry.get("match") and entry["match"] not in text:
            continue
        if entry.get("expires", "") < today:
            continue
        if entry.get("unfixed_only") and fixed:
            continue
        used = {k: entry[k] for k in ("id", "match", "unfixed_only", "reason", "expires") if k in entry}
        if record and used not in _applied:
            _applied.append(used)
        return used
    return None


def summarize(items, key, limit=8):
    return ", ".join(sorted({key(i) for i in items})[:limit])


# --- G1 ---------------------------------------------------------------------


def reviewers(path):
    """Latest review per reviewer, author excluded; only approvals of the
    current head count — an approval of an older revision didn't review
    what's actually being merged."""
    author, head, required = env("AUTHOR"), env("HEAD_SHA"), int(env("REQUIRED_APPROVALS", "1"))
    latest = {}
    for r in load_jsonl(path) or []:
        if r["user"]["login"] != author and r["state"] not in ("COMMENTED", "PENDING"):
            latest[r["user"]["login"]] = r
    approvals = sorted(u for u, r in latest.items() if r["state"] == "APPROVED" and r["commit_id"] == head)
    blocking = sorted(u for u, r in latest.items() if r["state"] == "CHANGES_REQUESTED")
    detail = f"{len(approvals)} of {required} required approval(s) on head {head[:7]} (author {author} excluded)"
    if blocking:
        detail += f"; changes requested by {', '.join(blocking)}"
    return len(approvals) >= required and not blocking, detail, {"approvals": len(approvals), "required": required}


def commits(path):
    """commits.tsv: short sha, GitHub's verified flag, reason."""
    with open(path) as f:
        rows = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    unsigned = [f"{sha} ({reason})" for sha, verified, reason in rows if verified != "true"]
    for sha, verified, reason in rows:
        if verified != "true":
            found("high", sha, f"commit not verified by GitHub ({reason})", blocking=True,
                  fix="sign it with a key registered to your GitHub account (git commit -S), or re-create it via the web UI")
    detail = f"{len(unsigned)} of {len(rows)} commit(s) unsigned/unverified" + (f": {', '.join(unsigned[:6])}" if unsigned else "")
    return bool(rows) and not unsigned, detail, None


def tests(pattern):
    """JUnit files → passed/total. A skipped test is excluded from the
    total, and zero tests is a fail, so skipping everything can't pass.
    RC is the test command's exit code (also catches collection errors)."""
    passed = total = 0
    for path in glob.glob(pattern, recursive=True):
        for case in ET.parse(path).getroot().iter("testcase"):  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
            tags = {child.tag for child in case}
            if "skipped" in tags:
                continue
            total += 1
            passed += not tags & {"failure", "error"}
            for bad in (c for c in case if c.tag in ("failure", "error")):
                found("high", f"{case.get('classname', '')}::{case.get('name', '')}".strip(":"),
                      f"{bad.tag}: {first_line(bad.get('message') or bad.text)}", blocking=True,
                      file=case.get("file"), line=case.get("line") and int(case.get("line")) + 1)
    ok = env("RC") == "0" and total > 0 and passed == total
    if not total:
        tool_broke()
    return ok, f"{passed}/{total} passed ({env('LABEL', pattern)})", {"tests_passed": passed, "tests_total": total}


def coverage(path):
    threshold = float(env("COVERAGE_THRESHOLD"))
    try:
        rate = ET.parse(path).getroot().get("line-rate")  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
    except (OSError, ET.ParseError):
        rate = None
    if rate is None:
        return False, "no coverage report", {"coverage_pct": 0.0, "threshold_pct": threshold}
    cov = float(rate) * 100
    return cov >= threshold, f"{cov:.1f}% line coverage vs threshold {threshold:.0f}% (pytest-cov, unit tests)", {"coverage_pct": round(cov, 2), "threshold_pct": threshold}


def semgrep(path):
    """ERROR (High) and WARNING (Medium) block; INFO is reported."""
    report = load(path)
    if report is None:
        return missing("semgrep")
    results = []
    for r in report.get("results", []):
        extra, a = r["extra"], accepted(r["check_id"], r.get("path", ""))
        meta = extra.get("metadata") or {}
        found({"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(extra.get("severity")), r["check_id"],
              first_line(extra.get("message")), blocking=extra.get("severity") in ("ERROR", "WARNING"), accepted=a,
              file=r.get("path"), line=r["start"]["line"], url=meta.get("source"),
              fix=f"autofix: {first_line(extra['fix'], 120)}" if extra.get("fix") else None)
        if not a:
            results.append(r)
    blocking = [r for r in results if r["extra"].get("severity") in ("ERROR", "WARNING")]
    errors = report.get("errors") or []
    rules = summarize(blocking, lambda r: f"{r['check_id'].rsplit('.', 1)[-1]} ({r['path']}:{r['start']['line']})", 6)
    detail = f"{len(blocking)} High/Medium of {len(results)} findings, {len(errors)} scan error(s){': ' + rules if rules else ''}"
    return not blocking, detail, {"findings": len(results), "blocking": len(blocking)}


def gitleaks(path):
    report = load(path)
    if report is None:
        return missing("gitleaks")
    leaks = []
    for r in report:
        a = accepted(r.get("RuleID", ""), r.get("File", ""))
        found("high", r.get("RuleID", ""), first_line(r.get("Description")), blocking=True, accepted=a,
              file=r.get("File"), line=r.get("StartLine"), where=f"commit {r.get('Commit', '')[:7]}",
              fix="treat it as leaked: rotate/revoke it first (git history keeps it), then load it from the environment")
        if not a:
            leaks.append(r)
    where = summarize(leaks, lambda r: f"{r['RuleID']} ({r['File']}:{r['StartLine']} @{r.get('Commit', '')[:7]})", 6)
    return not leaks, f"{len(leaks)} leak(s) in {env('SCOPE', 'the repository')} (values redacted){': ' + where if where else ''}", {"leaks": len(leaks)}


def trufflehog(path):
    """Verified (live) credentials block; unverified candidates are
    reported, since most are test fixtures or dead keys."""
    rows = load_jsonl(path)
    if rows is None:
        return missing("trufflehog")
    kept = []
    for r in (r for r in rows if "DetectorName" in r):
        a = accepted(r["DetectorName"])
        git = ((r.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {}
        found("critical" if r.get("Verified") else "low", r["DetectorName"],
              "verified LIVE credential" if r.get("Verified") else "unverified candidate (not confirmed live)",
              blocking=bool(r.get("Verified")), accepted=a, file=git.get("file"), line=git.get("line"),
              where=f"commit {str(git.get('commit', ''))[:7]}",
              fix="revoke it at the provider now, then remove it from the code" if r.get("Verified") else None)
        if not a:
            kept.append(r)
    rows = kept
    verified = [r for r in rows if r.get("Verified")]
    where = summarize(verified, lambda r: f"{r['DetectorName']} ({((r.get('SourceMetadata') or {}).get('Data') or {}).get('Git', {}).get('file', '?')})", 6)
    detail = f"{len(verified)} verified live credential(s), {len(rows) - len(verified)} unverified candidate(s) in full git history{': ' + where if where else ''}"
    if env("RC") != "0":
        tool_broke()
    return env("RC") == "0" and not verified, detail, {"verified": len(verified), "unverified": len(rows) - len(verified)}


# --- G2 ---------------------------------------------------------------------


def build(dockerfile):
    """Config controlled (every base ref digest-pinned) and reproducible
    (cached build == --no-cache build, env D1/D2)."""
    refs, bad = [], []
    with open(dockerfile) as f:
        for line in f:
            m = re.match(r"\s*#\s*syntax=(\S+)", line) or re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", line, re.I)
            if m and not re.fullmatch(r"[a-z][\w-]*", m.group(1)):  # FROM <earlier stage> isn't a base ref
                refs.append(m.group(1))
                if not re.search(r"@sha256:[0-9a-f]{64}$", m.group(1)):
                    bad.append(m.group(1))
    pins = f"{len(refs) - len(bad)}/{len(refs)} base refs digest-pinned" + (f" (unpinned: {', '.join(bad)})" if bad else "")
    d1, d2 = env("D1"), env("D2")
    if env("RC") != "0" or not d1 or not d2:
        ok, repro = False, "build failed"
    elif d1 != d2:
        # REPRO_REQUIRED=0 records a measured mismatch as a finding instead of
        # failing the control. Used where the CI builder itself is the
        # nondeterministic part and the source has been shown to be
        # reproducible elsewhere; the mismatch still reaches the evidence.
        if env("REPRO_REQUIRED") == "0":
            found("medium", "reproducible-build",
                  f"two fresh builds of the same source produced {d1[:19]} and {d2[:19]}",
                  blocking=False, where="Build · image (reproducible)",
                  fix="deterministic builder or a fixed SOURCE_DATE_EPOCH; the digest comparison is recorded, not enforced, on this repo")
            ok, repro = True, f"measured NOT reproducible: {d1[:19]} vs {d2[:19]} (recorded, REPRO_REQUIRED=0)"
        else:
            ok, repro = False, f"NOT reproducible: {d1[:19]} vs {d2[:19]} (two --no-cache builds)"
    else:
        ok, repro = True, f"reproducible: two --no-cache builds both {d1[:19]} (same runner)"
    return ok and bool(refs) and not bad, f"{repro}; {pins}", None


def trivy_fs(path):
    """SCA from the lockfile: a Critical/High WITH a released fix blocks (bump
    it), one with no fix is reported and counted but does not break the
    pipeline, and an unrated one only blocks when a fix exists. Same rule as
    the image scan (`--ignore-unfixed`) and trivy(): the pipeline asks for
    work that can actually be done. Zero packages scanned is still a fail
    (the lockfile wasn't understood)."""
    report = load(path)
    if report is None:
        return missing("trivy")
    results = report.get("Results") or []
    packages = sum(len(r.get("Packages") or []) for r in results)
    blocking, lower = [], 0
    for r in results:
        # The lockfile line comes from the package, not the vulnerability.
        lines = {(p.get("Identifier") or {}).get("UID"): (p.get("Locations") or [{}])[0].get("StartLine") for p in r.get("Packages") or []}
        for v in r.get("Vulnerabilities") or []:
            a = accepted(v["VulnerabilityID"], fixed=bool(v.get("FixedVersion")))
            fixable = bool(v.get("FixedVersion"))
            block = fixable and v.get("Severity") in ("CRITICAL", "HIGH", "UNKNOWN", None)
            found(v.get("Severity"), v["VulnerabilityID"], v.get("Title") or first_line(v.get("Description")), blocking=block, accepted=a,
                  package=v["PkgName"], version=v.get("InstalledVersion"), file=r.get("Target"),
                  line=lines.get((v.get("PkgIdentifier") or {}).get("UID")), url=v.get("PrimaryURL"),
                  fixed_version=v.get("FixedVersion"),
                  fix=f"upgrade to {v['FixedVersion']}" if v.get("FixedVersion") else "no fixed release: replace or remove the dependency")
            if a:
                continue
            if block:
                blocking.append(v)
            else:
                lower += 1
    top = summarize(blocking, lambda v: f"{v['VulnerabilityID']} ({v['PkgName']} {v.get('InstalledVersion', '')} {v.get('Severity') or 'no severity'})")
    unfixed = [v for r in results for v in r.get("Vulnerabilities") or [] if not v.get("FixedVersion")]
    detail = (f"{len(blocking)} High/Critical-or-unrated with a fix, {len(unfixed)} without a fix (noted, not blocking), {lower} lower, across {packages} packages "
              f"({', '.join(r.get('Target', '?') for r in results) or env('LOCKFILE', 'lockfile')}){': ' + top if top else ''}")
    if not packages:
        tool_broke()
    return packages > 0 and not blocking, detail, {"packages": packages, "blocking": len(blocking)}


def checkov(path):
    """Open-source checkov has no severities, so every failed check blocks;
    exceptions are inline `checkov.io/skipN` annotations, counted here."""
    reports = load(path)
    if reports is None:
        return missing("checkov")
    reports = reports if isinstance(reports, list) else [reports]
    passed = sum(r.get("summary", {}).get("passed", 0) for r in reports)
    failed = [c for r in reports for c in r.get("results", {}).get("failed_checks", [])]
    skipped = sorted({c["check_id"] for r in reports for c in r.get("results", {}).get("skipped_checks", [])})
    for c, status in [(c, "failed") for c in failed] + [(c, "skipped") for r in reports for c in r.get("results", {}).get("skipped_checks", [])]:
        # Paths are the scan copy (input/). A copy of a repo file anchors to
        # it; a render (kustomize) has no file to point at.
        path = (c.get("repo_file_path") or c.get("file_path") or "").split("/input/", 1)[-1]
        in_repo = os.path.isfile(path)
        inline = {"reason": (c.get("check_result") or {}).get("suppress_comment") or "inline checkov:skip", "expires": None}
        found(c.get("severity"), c["check_id"], c.get("check_name"), blocking=status == "failed", accepted=inline if status == "skipped" else None,
              file=path if in_repo else None, line=(c.get("file_line_range") or [None])[0] if in_repo else None,
              where=None if in_repo else f"{c.get('resource')} (kustomize build deploy/prod)", url=c.get("guideline"),
              fix="fix it, or skip inline with a reason: " + ("`# checkov:skip=ID:reason`" if path.endswith("Dockerfile") else "`checkov.io/skipN` annotation"))
    ids = summarize(failed, lambda c: f"{c['check_id']} ({c['resource']})")
    detail = (f"{len(failed)} failed, {passed} passed, {len(skipped)} skipped with inline justification"
              f"{' (' + ', '.join(skipped) + ')' if skipped else ''} — {', '.join(r.get('check_type', '?') for r in reports)}"
              f"{': ' + ids if ids else ''}")
    if not failed and not passed:
        tool_broke()
    return not failed and passed > 0, detail, {"failed": len(failed), "passed": passed}


def trivy(path):
    """Critical/High with a released fix block; ones with no upstream fix
    are reported but don't block (BLOCK_UNFIXED=true to block them too).
    Any embedded secret blocks. Plus "hardened base": a non-root USER."""
    report = load(path)
    if report is None:
        return missing("trivy")
    block_unfixed = env("BLOCK_UNFIXED") == "true"
    vulns, secrets = [], []
    for r in report.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            a = accepted(v["VulnerabilityID"], fixed=bool(v.get("FixedVersion")))
            found(v.get("Severity"), v["VulnerabilityID"], v.get("Title") or first_line(v.get("Description")),
                  blocking=block_unfixed or bool(v.get("FixedVersion")), accepted=a, package=v["PkgName"],
                  version=v.get("InstalledVersion"), where=r.get("Target"), url=v.get("PrimaryURL"), fixed_version=v.get("FixedVersion"),
                  fix=f"upgrade to {v['FixedVersion']} (rebuild on a patched base, or bump the package)" if v.get("FixedVersion") else "no upstream fix yet")
            if not a:
                vulns.append(v)
        for s in r.get("Secrets") or []:
            a = accepted(s.get("RuleID", ""))
            found(s.get("Severity"), s.get("RuleID", ""), s.get("Title"), blocking=True, accepted=a,
                  where=f"{r.get('Target')}:{s.get('StartLine', '')} (in the image)", fix="rotate it, and keep it out of the build context (.dockerignore)")
            if not a:
                secrets.append(s)
    blocking = vulns if block_unfixed else [v for v in vulns if v.get("FixedVersion")]
    unfixed = [v for v in vulns if not v.get("FixedVersion")]
    top = summarize(blocking, lambda v: f"{v['VulnerabilityID']} ({v['PkgName']})")
    user = ((report.get("Metadata") or {}).get("ImageConfig") or {}).get("config", {}).get("User", "").strip()
    root = user.split(":")[0] in ("", "0", "root")
    if root:
        found("high", "image-runs-as-root", f"image user is {user or 'unset (root)'}", blocking=True, file="Dockerfile",
              fix="add `USER <non-root uid>` to the final stage")
    detail = (f"{len(blocking)} fixable Critical/High{': ' + top if top else ''}; {len(unfixed)} without an upstream fix "
              f"({'blocking' if block_unfixed else 'reported, not blocking'}); {len(secrets)} embedded secret(s); "
              f"runs as {user or 'root (no USER)'}; base {env('BASE_IMAGE', '?')[:40]}")
    return not blocking and not secrets and not root, detail, {"blocking": len(blocking), "unfixed": len(unfixed)}


def sbom(path):
    bom = load(path)
    if bom is None:
        return missing("syft")
    n = len(bom.get("components") or [])
    return bom.get("bomFormat") == "CycloneDX" and n > 0, f"CycloneDX {bom.get('specVersion')} with {n} components (syft, from the built image)", {"components": n}


def signed():
    """A signature is the statement "this passed every static control":
    only signed when they all passed (NOT_READY lists the ones that
    didn't), and a pass means the pushed digest is the built one and the
    signature and attestations verify (VERIFY_FAILED)."""
    if env("NOT_READY"):
        return False, f"not published or signed: controls failed ({env('NOT_READY')})", None
    if env("VERIFY_FAILED"):
        return False, f"publish/sign ran but verification failed:{env('VERIFY_FAILED')}", None
    return True, ("pushed digest == built digest; cosign keyless signature + CycloneDX SBOM and SLSA v1 provenance "
                  f"attestations verified for {env('CERT_IDENTITY', '').split('/', 5)[-1]} (public Rekor); GitHub build provenance attested"), None


# --- G3 ---------------------------------------------------------------------


def dockle(path):
    """FATAL and WARN block; INFO is reported."""
    report = load(path)
    if report is None:
        return missing("dockle")
    details = report.get("details") or []
    kept = []
    for d in details:
        # Accepted only if every alert is; only then are the entries "applied".
        hits = [accepted(d["code"], a, record=False) for a in (d.get("alerts") or [""])]
        if all(hits):
            hits = [accepted(d["code"], a) for a in (d.get("alerts") or [""])]
        found({"FATAL": "high", "WARN": "medium", "INFO": "low"}.get(d["level"], "info"), d["code"], d.get("title"),
              blocking=d["level"] in ("FATAL", "WARN"), accepted=hits[0] if all(hits) else None,
              where="; ".join(d.get("alerts") or [])[:300], url=f"https://github.com/goodwithtech/dockle#{d['code'].lower()}")
        if not all(hits):
            kept.append(d)
    blocking = [d for d in kept if d["level"] in ("FATAL", "WARN")]
    ids = summarize(blocking, lambda d: f"{d['code']} {d['title']}")
    return not blocking, f"{len(blocking)} FATAL/WARN of {len(kept)} findings (CIS Docker Benchmark + dockle checks){': ' + ids if ids else ''}", None


def frappe_migrate(path):
    """The built image boots, creates its site, installs the app and applies
    the app's schema to a real MariaDB. RC is the migrate exit code.

    A Frappe app ships data, not just code: doctype JSONs, patches, fixtures.
    None of that is exercised by a linter or by importing the module, so a
    broken schema is only visible when the artifact migrates. This is the
    Django demo's `check --deploy` slot, filled with the check Frappe has.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            out = f.read()
    except OSError:
        return missing("frappe bench migrate")
    crashed = "Traceback (most recent call last)" in out
    migrated = bool(re.search(r"^(Migrating|Updating DocTypes)", out, re.M))
    synced = "Updating DocTypes for frappe_gates_demo" in out
    installed = bool(re.search(r"Installing frappe_gates_demo", out))
    for line in out.splitlines():
        if re.search(r"Error|Traceback", line):
            found("high", "migrate", first_line(line), blocking=True,
                  where="bench --site <site> migrate (in the image)",
                  fix="fix the doctype/patch the migration could not apply")
    if not migrated:
        tool_broke()
        _state["log"] = out[-4000:]
    ok = env("RC") == "0" and migrated and synced and not crashed
    detail = (
        f"{'site created + app installed + ' if installed else ''}"
        f"{'doctypes synced for frappe_gates_demo' if synced else 'doctypes NOT synced'}"
        f"{'; migration crashed' if crashed else ''} (bench migrate in the image, no source tree)"
    )
    return ok, detail, None


def k6(path):
    summary = load(path)
    if summary is None:
        return missing("k6")
    m = summary.get("metrics", {})
    val = lambda name, stat: (m.get(name, {}).get("values") or {}).get(stat)  # noqa: E731
    p95, failed, checks, slo = val("http_req_duration", "p(95)"), val("http_req_failed", "rate") or 0, val("checks", "rate") or 0, float(env("SLO_P95_MS"))
    reqs = val("http_reqs", "count") or 0
    if p95 is None:
        return False, "k6 summary has no http_req_duration", None
    ok = p95 <= slo and failed < 0.01 and checks >= 0.99
    detail = f"p95 {p95:.0f} ms vs SLO {slo:.0f} ms; {100 * failed:.2f}% failed of {reqs} requests, {100 * checks:.1f}% checks ok (authenticated, via TLS proxy)"
    return ok, detail, {"p95_ms": round(p95, 1), "slo_ms": slo, "requests": reqs}


def nuclei(path):
    """Medium+ block; low is reported."""
    rows = load_jsonl(path)
    if rows is None:
        return missing("nuclei")
    kept = []
    for r in rows:
        a, info = accepted(r.get("template-id", "")), r.get("info") or {}
        found(info.get("severity"), r.get("template-id", ""), info.get("name"), blocking=info.get("severity") in ("medium", "high", "critical"),
              accepted=a, where=r.get("matched-at"), url=r.get("template-url"), fix=first_line(info.get("remediation"), 160) or None)
        if not a:
            kept.append(r)
    rows = kept
    blocking = [r for r in rows if (r.get("info") or {}).get("severity") in ("medium", "high", "critical")]
    ids = summarize(blocking, lambda r: f"{r['template-id']} ({r['info']['severity']})")
    if env("RC") != "0":
        tool_broke()
    detail = f"{len(blocking)} Medium+ of {len(rows)} findings — nuclei {env('TEMPLATES', '')} (dos/fuzz/intrusive excluded){': ' + ids if ids else ''}"
    return env("RC") == "0" and not blocking, detail, {"findings": len(rows), "blocking": len(blocking)}


def testssl(path):
    """HIGH and CRITICAL block; certificate-issuance findings caused by the
    ephemeral internal CA are accepted in the register (by id)."""
    report = load(path)
    if report is None:
        return missing("testssl.sh")
    scans = report.get("scanResult") or []
    findings = []
    for scan in scans:
        for section, items in scan.items():
            if isinstance(items, list):
                findings += [i for i in items if isinstance(i, dict) and "severity" in i]
    # Per-certificate ids carry a suffix ("intermediate_cert_notAfter <#1>").
    kept = []
    for f in findings:
        a = accepted(re.sub(r"\s*<#\d+>$", "", f.get("id", "")))
        if f["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "FATAL"):
            found("high" if f["severity"] == "FATAL" else f["severity"], f.get("id", ""),
                  ("testssl.sh could not test this: " if f["severity"] == "FATAL" else "") + first_line(f.get("finding")),
                  blocking=f["severity"] in ("HIGH", "CRITICAL", "FATAL"), accepted=a, where=os.environ.get("TARGET_URL") or "https://localhost:18443 (environment TLS proxy)")
        if not a:
            kept.append(f)
    blocking = [f for f in kept if f["severity"] in ("HIGH", "CRITICAL")]
    fatal = [f for f in kept if f["severity"] == "FATAL"]
    ids = summarize(blocking + fatal, lambda f: f"{f['id']} ({f['severity']})")
    detail = f"{len(blocking)} High/Critical of {len(findings)} TLS checks (testssl.sh: protocols, ciphers, vulnerabilities, headers){': ' + ids if ids else ''}"
    if not scans or not findings or fatal:
        tool_broke()
    return bool(scans) and bool(findings) and not blocking and not fatal, detail, {"checks": len(findings), "blocking": len(blocking)}


# --- G5 ---------------------------------------------------------------------


def kubeconform(path):
    """Render valid against schemas (-strict) AND the only change vs git
    is the image digest (CHANGED, space-separated paths)."""
    summary = (load(path) or {}).get("summary", {})
    valid = summary.get("valid", 0)
    total = sum(summary.get(k, 0) for k in ("valid", "invalid", "errors", "skipped"))
    changed = (env("CHANGED") or "").split()
    kustomization = env("KUSTOMIZATION", "deploy/prod/kustomization.yaml")
    # No change vs git is the correct outcome when the environment already runs
    # this digest (the release was re-dispatched for it, or a retry landed on the
    # same image): the render must still have referenced the digest, which the
    # workflow asserts before calling this, and any other drift would show up as
    # a changed path and fail here.
    already_pinned = env("ALREADY_PINNED") == "1"
    ok = env("RC") == "0" and total > 0 and valid == total and (changed == [kustomization] or (already_pinned and not changed))
    if already_pinned and not changed:
        detail = f"{os.path.dirname(kustomization)} render: {valid}/{total} resources valid (kubeconform -strict); change vs git: none — already pinned to the promoted digest, nothing to commit"
    else:
        detail = f"{os.path.dirname(kustomization)} render: {valid}/{total} resources valid (kubeconform -strict); change vs git: {', '.join(changed) or 'none'} (image digest only)"
    return ok, detail, None


# --- code quality -----------------------------------------------------------


def ruff(path):
    """Every finding blocks: the threshold is the rule set and mccabe
    max-complexity in pyproject.toml [tool.ruff.lint], quoted in the detail
    so the evidence says what "met" meant."""
    report = load(path)
    if report is None:
        return missing("ruff")
    with open(env("PYPROJECT", "pyproject.toml"), "rb") as f:
        lint = tomllib.load(f).get("tool", {}).get("ruff", {}).get("lint", {})
    limit = lint.get("mccabe", {}).get("max-complexity")
    root = os.getcwd() + os.sep
    worst = 0
    for r in report:
        file = r["filename"].removeprefix(root)
        m = re.search(r"\((\d+) > \d+\)", r["message"]) if r["code"] == "C901" else None
        worst = max(worst, int(m.group(1))) if m else worst
        found("medium", r["code"], r["message"], blocking=True, file=file, line=r["location"]["row"], url=r.get("url"))
    rules = summarize(report, lambda r: f"{r['code']} ({r['filename'].removeprefix(root)}:{r['location']['row']})", 6)
    detail = (f"{len(report)} finding(s) vs threshold 0 (rules {','.join(lint.get('select', []))}; "
              f"function complexity <= {limit}){': ' + rules if rules else ''}")
    return not report, detail, {"findings": len(report), "max_complexity_allowed": limit, "worst_complexity_over": worst or None}


def health(path):
    """The prod health watch after the rollout (devsecops-stage.yml): every
    /api/method/frappe_gates_demo.api.health probe answered 200, their p95 latency within SLO_P95_MS, and no
    container of the app restarted while it was watched."""
    report = load(path)
    if report is None:
        return missing("health watch")
    probes = report.get("probes") or []
    if not probes:
        return False, "health watch recorded no probes", None
    slo = float(env("SLO_P95_MS", "500"))
    bad = [p for p in probes if p.get("code") != 200]
    ms = sorted(float(p.get("ms") or 0) for p in probes)
    p95 = ms[max(0, round(0.95 * len(ms)) - 1)]
    before, after = report.get("restarts_before") or {}, report.get("restarts_after") or {}
    restarted = sorted(k for k, n in after.items() if n > before.get(k, n))
    for p in bad[:20]:
        found("high", "healthz", f"/api/method/frappe_gates_demo.api.health answered {p.get('code') or 'no response'} at {p.get('at')}", blocking=True)
    for k in restarted:
        found("high", "restart", f"container {k} restarted during the watch ({before.get(k)} → {after.get(k)})", blocking=True)
    if p95 > slo:
        found("medium", "latency", f"/api/method/frappe_gates_demo.api.health p95 {p95:.0f} ms > SLO {slo:.0f} ms", blocking=True)
    ok = not bad and not restarted and p95 <= slo
    detail = (f"{len(probes) - len(bad)}/{len(probes)} probes healthy over {report.get('seconds')} s, p95 {p95:.0f} ms "
              f"(SLO {slo:.0f} ms), {len(restarted)} restart(s) across {len(after)} container(s)")
    return ok, detail, {"probes": len(probes), "failed_probes": len(bad), "p95_ms": round(p95), "restarts": len(restarted)}


# --- generic ----------------------------------------------------------------


def result(status, detail):
    """For controls decided in shell (API checks, verification commands).
    `skipped` = not evaluated in this context (says why in detail); it
    never counts as a pass — gate.py decides whether it may be skipped."""
    return ("skipped" if status == "skipped" else status == "pass"), detail, None


CHECKS = {f.__name__.replace("_", "-"): f for f in (
    reviewers, commits, tests, coverage, semgrep, gitleaks, trufflehog,
    build, trivy_fs, checkov, trivy, sbom, signed,
    dockle, frappe_migrate, k6, nuclei, testssl, kubeconform, ruff, health, result,
)}


def main():
    check, args = sys.argv[1], sys.argv[2:]
    try:
        ok, detail, metrics = CHECKS[check](*args)
    except (OSError, ValueError, KeyError, TypeError, IndexError, ET.ParseError) as exc:
        ok, detail, metrics = False, f"{check}: could not evaluate ({type(exc).__name__}: {exc})", None
        tool_broke()
    out = {"status": "skipped" if ok == "skipped" else "pass" if ok else "fail", "detail": detail[:1000]}
    if env("TOOL"):
        out["tool"] = env("TOOL")
    if metrics:
        out["metrics"] = metrics
    if _applied:
        out["accepted"] = _applied
        ids = sorted({a["id"] for a in _applied})
        listed = ", ".join(ids) if len(ids) <= 5 else f"{len(ids)} ids, listed in `accepted`"
        out["detail"] = (out["detail"] + f"; accepted risks applied: {listed}")[:1000]
    print(f"{out['status']}: {out['detail']}")
    if env("GITHUB_OUTPUT"):
        with open(env("GITHUB_OUTPUT"), "a") as f:
            f.write(f"{env('OUTPUT', 'result')}={json.dumps(out)}\n")
    kind = _state["kind"] or ("findings" if any(f["status"] == "blocking" for f in _findings) else "policy")
    findings.publish(CONTROL or check, check, out, _findings, kind, os.path.dirname(env("VERDICT_FILE", "")), log=_state.get("log"))
    if env("VERDICT_FILE"):
        os.makedirs(os.path.dirname(env("VERDICT_FILE")) or ".", exist_ok=True)
        with open(env("VERDICT_FILE"), "w") as f:
            json.dump({"control": CONTROL, "check": check, **out}, f, indent=2)
    if out["status"] == "fail":
        print(f"::error title={CONTROL or check}::{out['detail'][:500]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
