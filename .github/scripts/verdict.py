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


def cwe_of(*values):
    """The first CWE number in what a tool reports ("CWE-79: ...",
    ["cwe-89"], "CWE-310"), or None."""
    for value in values:
        for item in value if isinstance(value, (list, tuple)) else [value]:
            m = re.search(r"cwe[-_ ]?(\d+)", str(item or ""), re.I)
            if m:
                return int(m.group(1))
    return None


def owasp_of(value):
    """The OWASP Top 10 category ("A03:2021") in semgrep's metadata, or None."""
    for item in value if isinstance(value, (list, tuple)) else [value]:
        m = re.search(r"A\d{2}:20\d{2}", str(item or ""))
        if m:
            return m.group(0)
    return None


# OWASP Top 10 (2021) category for findings whose tool doesn't name one.
OWASP_COMPONENTS = "A06:2021"       # vulnerable and outdated components
OWASP_MISCONFIG = "A05:2021"        # security misconfiguration
OWASP_CREDENTIALS = "A07:2021"      # identification and authentication failures (hard-coded secrets)
OWASP_CRYPTO = "A02:2021"           # cryptographic failures (TLS)


def xml_root(path):
    """The root element of an XML report this job wrote (JUnit, coverage),
    parsed with defusedxml: no external entities, no DTD tricks, no
    entity-expansion bombs (what semgrep's use-defused-xml rules ask for).
    Imported here, not at the top, so every other control keeps running on
    the bare runner's python3; the jobs that parse XML run this script with
    `uv run --with defusedxml`. Any unreadable or refused report is a
    ValueError."""
    from defusedxml.ElementTree import parse

    try:
        return parse(path).getroot()
    except OSError:
        raise
    except Exception as exc:  # ParseError, DTDForbidden, EntitiesForbidden...
        raise ValueError(f"{path}: not a usable XML report ({type(exc).__name__}: {exc})") from exc


def waivers(kind="an inline ignore comment"):
    """Blocking findings for every in-repo waiver a scanner would honour
    silently (INLINE_IGNORES: "<file>:<line>:<what>" lines, written by the
    job): exceptions come from the central risk register only, never from
    the code under review. Returns how many there were."""
    try:
        with open(env("INLINE_IGNORES") or "") as f:
            hits = [line.strip() for line in f if line.strip()]
    except OSError:
        return 0
    for hit in hits:
        file, _, rest = hit.partition(":")
        line, _, what = rest.partition(":")
        found("high", "in-repo-waiver", f"{what or kind}: exceptions come from the central risk register only",
              blocking=True, file=file.removeprefix("./"), line=int(line) if line.isdigit() and line != "0" else None,
              fix="remove it, and raise an exception request in the security dashboard if the finding is acceptable")
    return len(hits)


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
        for case in xml_root(path).iter("testcase"):
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
        rate = xml_root(path).get("line-rate")
    except (OSError, ValueError):
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
              cwe=cwe_of(meta.get("cwe")), owasp=owasp_of(meta.get("owasp")),
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
              cwe=798, owasp=OWASP_CREDENTIALS,
              fix="treat it as leaked: rotate/revoke it first (git history keeps it), then load it from the environment")
        if not a:
            leaks.append(r)
    where = summarize(leaks, lambda r: f"{r['RuleID']} ({r['File']}:{r['StartLine']} @{r.get('Commit', '')[:7]})", 6)
    refused = waivers("a gitleaks config file")
    extra = f"; {refused} in-repo gitleaks config (not allowed)" if refused else ""
    return not leaks and not refused, f"{len(leaks)} leak(s) in {env('SCOPE', 'the repository')} (values redacted){extra}{': ' + where if where else ''}", {"leaks": len(leaks)}


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
              where=f"commit {str(git.get('commit', ''))[:7]}", cwe=798, owasp=OWASP_CREDENTIALS,
              fix="revoke it at the provider now, then remove it from the code" if r.get("Verified") else None)
        if not a:
            kept.append(r)
    rows = kept
    verified = [r for r in rows if r.get("Verified")]
    where = summarize(verified, lambda r: f"{r['DetectorName']} ({((r.get('SourceMetadata') or {}).get('Data') or {}).get('Git', {}).get('file', '?')})", 6)
    refused = waivers("an inline trufflehog:ignore")
    detail = (f"{len(verified)} verified live credential(s), {len(rows) - len(verified)} unverified candidate(s) in full git history"
              f"{f'; {refused} inline trufflehog:ignore (not allowed)' if refused else ''}{': ' + where if where else ''}")
    if env("RC") != "0":
        tool_broke()
    return env("RC") == "0" and not verified and not refused, detail, {"verified": len(verified), "unverified": len(rows) - len(verified)}


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
                  fixed_version=v.get("FixedVersion"), cwe=cwe_of(v.get("CweIDs")), owasp=OWASP_COMPONENTS,
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


def _k8s_objects(message):
    """The Kubernetes objects a trivy message names ("Container 'mariadb' of
    StatefulSet 'frappe-gates-demo-mariadb'" -> "Container mariadb, StatefulSet
    frappe-gates-demo-mariadb"): a rendered manifest has no repo file to anchor
    on, and these are stable where line numbers in a render are not."""
    return ", ".join(f"{kind} {name}" for kind, name in re.findall(r"\b([A-Z][A-Za-z]+) '([^']+)'", message or ""))


def trivy_config(path, render="kustomize build deploy/prod"):
    """trivy config (IaC): every IaC file in the repository, of every type
    trivy supports (Dockerfiles, Kubernetes, Helm, Terraform, CloudFormation,
    Azure ARM, Ansible), plus the rendered manifests (targets "rendered/...").
    Critical/High block; Medium/Low are reported. Exceptions come from the
    central register only (id, optional scope on the file, the resource or
    Kubernetes object, and the message): an inline ignore comment or an
    ignore/config file in the repo, which trivy would honour silently, fails
    the control (INLINE_IGNORES lists them)."""
    report = load(path)
    if report is None:
        return missing("trivy config")
    results = report.get("Results") or []
    # The render first: a Kubernetes object in deploy/base and in the render
    # is one finding (anchored on the object), reported where it is deployed.
    results = sorted(results, key=lambda r: not (r.get("Target") or "").startswith("rendered/"))
    checks = sum((r.get("MisconfSummary") or {}).get("Successes", 0) + (r.get("MisconfSummary") or {}).get("Failures", 0) for r in results)
    blocking, lower, seen, types = [], 0, set(), set()
    for r in results:
        target = r.get("Target") or ""
        rendered = target.startswith("rendered/")
        k8s = rendered or (r.get("Type") or "").lower() == "kubernetes"
        types.add("rendered manifests" if rendered else (r.get("Type") or "?"))
        for m in r.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            objects = _k8s_objects(m.get("Message")) if k8s else (cause.get("Resource") or "")
            if k8s:
                key = (m["ID"], objects)
                if objects and key in seen:
                    continue  # the same object in deploy/base and in the render
                seen.add(key)
            block = m.get("Severity") in ("CRITICAL", "HIGH")
            a = accepted(m["ID"], f"{target} {objects} {m.get('Message', '')}")
            line = cause.get("StartLine")
            found(m.get("Severity"), m["ID"], m.get("Title"), blocking=block, accepted=a,
                  # Files are anchored on their path; Kubernetes objects on the
                  # object (stable across deploy/base, the render and line moves).
                  file=None if k8s else target, line=None if k8s else line,
                  resource=objects or None,
                  where=(f"{objects or target} ({render})" if rendered else f"{target}:{line}" if line else target) if k8s else None,
                  url=m.get("PrimaryURL"), owasp=OWASP_MISCONFIG, fix=first_line(m.get("Resolution"), 160) or None)
            if a:
                continue
            if block:
                blocking.append(m)
            else:
                lower += 1
    inline = waivers("an inline ignore comment")
    ids = summarize(blocking, lambda m: f"{m['ID']} ({_k8s_objects(m.get('Message')) or (m.get('CauseMetadata') or {}).get('Resource') or m.get('Title', '')})")
    detail = (f"{len(blocking)} Critical/High, {lower} lower, {checks} checks (trivy config: {', '.join(sorted(types)) or 'nothing found to scan'})"
              f"{'; ' + str(inline) + ' inline ignore(s) or ignore file(s) (not allowed)' if inline else ''}{': ' + ids if ids else ''}")
    if not checks:
        tool_broke()
    return checks > 0 and not blocking and not inline, detail, {"blocking": len(blocking), "lower": lower, "checks": checks}


def trivy(path):
    """Critical/High (and unrated) with a released fix block; ones with no
    upstream fix are reported but don't block (BLOCK_UNFIXED=true to block
    them too); Medium/Low are reported. The scan keeps every severity (no
    --severity) but, by decision (2026-11-12: prioritise what can be fixed),
    runs with --ignore-unfixed: a vulnerability with no released fix isn't
    recorded until one exists. Any embedded secret blocks. Plus "hardened
    base": a non-root USER."""
    report = load(path)
    if report is None:
        return missing("trivy")
    block_unfixed = env("BLOCK_UNFIXED") == "true"
    vulns, secrets = [], []
    for r in report.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            a = accepted(v["VulnerabilityID"], fixed=bool(v.get("FixedVersion")))
            serious = v.get("Severity") in ("CRITICAL", "HIGH", "UNKNOWN", None)
            found(v.get("Severity"), v["VulnerabilityID"], v.get("Title") or first_line(v.get("Description")),
                  blocking=serious and (block_unfixed or bool(v.get("FixedVersion"))), accepted=a, package=v["PkgName"],
                  version=v.get("InstalledVersion"), where=r.get("Target"), url=v.get("PrimaryURL"), fixed_version=v.get("FixedVersion"),
                  cwe=cwe_of(v.get("CweIDs")), owasp=OWASP_COMPONENTS,
                  fix=f"upgrade to {v['FixedVersion']} (rebuild on a patched base, or bump the package)" if v.get("FixedVersion") else "no upstream fix yet")
            if not a:
                vulns.append(v)
        for s in r.get("Secrets") or []:
            a = accepted(s.get("RuleID", ""))
            found(s.get("Severity"), s.get("RuleID", ""), s.get("Title"), blocking=True, accepted=a,
                  where=f"{r.get('Target')}:{s.get('StartLine', '')} (in the image)", cwe=798, owasp=OWASP_CREDENTIALS,
                  fix="rotate it, and keep it out of the build context (.dockerignore)")
            if not a:
                secrets.append(s)
    serious = [v for v in vulns if v.get("Severity") in ("CRITICAL", "HIGH", "UNKNOWN", None)]
    blocking = serious if block_unfixed else [v for v in serious if v.get("FixedVersion")]
    unfixed = [v for v in serious if not v.get("FixedVersion")]
    top = summarize(blocking, lambda v: f"{v['VulnerabilityID']} ({v['PkgName']})")
    user = ((report.get("Metadata") or {}).get("ImageConfig") or {}).get("config", {}).get("User", "").strip()
    root = user.split(":")[0] in ("", "0", "root")
    if root:
        found("high", "image-runs-as-root", f"image user is {user or 'unset (root)'}", blocking=True, file="Dockerfile",
              cwe=250, owasp=OWASP_MISCONFIG,
              fix="add `USER <non-root uid>` to the final stage")
    detail = (f"{len(blocking)} fixable Critical/High{': ' + top if top else ''}; {len(unfixed)} Critical/High without an upstream fix "
              f"({'blocking' if block_unfixed else 'reported, not blocking'}); {len(vulns) - len(serious)} Medium/Low (reported); {len(secrets)} embedded secret(s); "
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
              where="; ".join(d.get("alerts") or [])[:300], url=f"https://github.com/goodwithtech/dockle#{d['code'].lower()}",
              owasp=OWASP_MISCONFIG)
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
    # The client in this job is one `kubectl port-forward` tunnel: every request
    # is multiplexed over a single connection to the API server, and the p95
    # follows host load (740 ms to 3000 ms measured on the same healthy app), not
    # the app. Asserting an SLO through that tunnel gates the machine, not the
    # service — so on this path the assertions are the ones that are truthful:
    # no failed requests and every functional check green. Set
    # K6_ASSERT_LATENCY=1 where the client is inside the cluster.
    assert_latency = env("K6_ASSERT_LATENCY", "1") != "0"
    ok = failed < 0.01 and checks >= 0.99 and (not assert_latency or p95 <= slo)
    if assert_latency:
        detail = f"p95 {p95:.0f} ms vs SLO {slo:.0f} ms; {100 * failed:.2f}% failed of {reqs} requests, {100 * checks:.1f}% checks ok (authenticated, via TLS proxy)"
    else:
        detail = (f"{100 * failed:.2f}% failed of {reqs} requests, {100 * checks:.1f}% checks ok under load "
                  f"(authenticated, via TLS proxy); latency not asserted on this path — the port-forward "
                  f"tunnel sets it (measured p95 {p95:.0f} ms), the 500 ms SLO is measured in-cluster")
    return ok, detail, {"p95_ms": round(p95, 1), "slo_ms": slo if assert_latency else None, "requests": reqs}


def nuclei(path):
    """Medium+ block; low is reported."""
    rows = load_jsonl(path)
    if rows is None:
        return missing("nuclei")
    kept = []
    for r in rows:
        a, info = accepted(r.get("template-id", "")), r.get("info") or {}
        found(info.get("severity"), r.get("template-id", ""), info.get("name"), blocking=info.get("severity") in ("medium", "high", "critical"),
              accepted=a, where=r.get("matched-at"), url=r.get("template-url"), fix=first_line(info.get("remediation"), 160) or None,
              cwe=cwe_of((info.get("classification") or {}).get("cwe-id")))
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
                  blocking=f["severity"] in ("HIGH", "CRITICAL", "FATAL"), accepted=a, where=os.environ.get("TARGET_URL") or "https://localhost:18443 (environment TLS proxy)",
                  cwe=cwe_of(f.get("cwe")), owasp=OWASP_CRYPTO)
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
    build, trivy_fs, trivy_config, trivy, sbom, signed,
    dockle, frappe_migrate, k6, nuclei, testssl, kubeconform, ruff, health, result,
)}


def main():
    check, args = sys.argv[1], sys.argv[2:]
    try:
        ok, detail, metrics = CHECKS[check](*args)
    except (OSError, ValueError, KeyError, TypeError, IndexError, ImportError) as exc:
        ok, detail, metrics = False, f"{check}: could not evaluate ({type(exc).__name__}: {exc})", None
        tool_broke()
    out = {"status": "skipped" if ok == "skipped" else "pass" if ok else "fail", "detail": detail[:1000]}
    if env("TOOL"):
        out["tool"] = env("TOOL")
    if metrics:
        out["metrics"] = metrics
    # Which register this verdict was graded against (the central register's
    # commit, written by .github/actions/accepted-risks), recorded on every
    # verdict, not only when an entry applied.
    source = (load(env("ACCEPTED_RISKS", "security/accepted-risks.json")) or {}).get("source")
    if source:
        out["accepted_risks_source"] = source
    if _applied:
        out["accepted"] = _applied
        ids = sorted({a["id"] for a in _applied})
        listed = ", ".join(ids) if len(ids) <= 5 else f"{len(ids)} ids, listed in `accepted`"
        out["detail"] = (out["detail"] + f"; accepted risks applied: {listed}" + (f" (register {source})" if source else ""))[:1000]
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
