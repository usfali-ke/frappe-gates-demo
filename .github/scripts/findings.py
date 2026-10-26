"""How a control's findings reach the developer.

verdict.py records each finding the same way whatever the tool
({status, severity, id, title, file/line or package, fix, url,
accepted}) and calls `publish()`, which writes, per control:

  findings.json    everything, uncapped (in the control's report artifact)
  findings.sarif   the file-anchored ones, for code scanning (public repos)
  job summary      blocking first, by severity, capped; fix, reproduce
                   command, accepted risks with expiry
  annotations      the first blocking findings that have a file and line
  accepted-ids.txt the ids of accepted findings, so a tool's own report
                   can leave them out (trivy --ignorefile, dockle -i)

Where the tool has a readable report of its own (trivy's table, checkov's
markdown, semgrep's text...), the job sets NATIVE to that file: the
summary then keeps only the verdict, the why, the upgrade plan and the
accepted risks, and `python3 findings.py native` shows the tool's report
under it (and in the log).

and `python3 findings.py pr-comment <reports> [<baseline>]` renders one PR
comment for the whole run from the downloaded report-* artifacts, with
what's new compared with main.

Nothing here decides pass/fail. Secret values never reach a finding:
the secret scanners' parsers only pass rule, file, line and commit.
"""

import datetime as dt
import json
import os
import re
import sys

env = os.environ.get

SEVERITIES = ("critical", "high", "unknown", "medium", "low", "info")
ICON = {"critical": "🟥", "high": "🟧", "unknown": "⬜", "medium": "🟨", "low": "🟦", "info": "▫️"}
LABEL = {"unknown": "Unrated"}
SARIF_SCORE = {"critical": "9.5", "high": "8.0", "unknown": "7.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
TABLE_CAP = 50
ANNOTATION_CAP = 9  # GitHub shows 10 errors per step; the verdict's own ::error is the tenth
KIND = {
    "tool": "The tool didn't produce a usable result (it crashed, or its report is missing), so nothing was checked. "
            "This is not a clean scan. Read the tool's output (below, or in the scan step's log).",
    "findings": "Blocking findings. Fix them, or, if a finding doesn't apply, add a reviewed entry with "
                "a reason and an expiry to `security/accepted-risks.json`.",
    "policy": "Policy not met (see the detail line). No individual findings to list.",
}


def rank(f):
    return (("blocking", "reported", "accepted").index(f["status"]), SEVERITIES.index(f["severity"]), f["id"], f.get("file") or "", f.get("line") or 0)


def key(f):
    """Identity across runs: line numbers move when code is edited above a
    finding, so they aren't part of it."""
    anchor = [f.get("file"), f.get("package")] if f.get("file") or f.get("package") else [f.get("where")]
    return "|".join(str(x or "") for x in [f["control"], f["id"], *anchor])


def md(text, limit=160):
    """One table cell: no newlines, pipes or HTML, no @mentions, bounded."""
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    text = text[: limit - 1] + "…" if len(text) > limit else text
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("@", "@​")


def where(f):
    if f.get("file"):
        return f"`{md(f['file'], 90)}{':' + str(f['line']) if f.get('line') else ''}`"
    if f.get("package"):
        return f"`{md(f['package'], 60)}{' ' + md(f['version'], 30) if f.get('version') else ''}`" + (f" in {md(f['where'], 60)}" if f.get("where") else "")
    return md(f.get("where"), 90)


def ident(f):
    text = f"`{md(f['id'], 70)}`"
    return f"[{text}]({f['url']})" if f.get("url") and f["url"].startswith("https://") else text


def sev(f):
    return f"{ICON[f['severity']]} {LABEL.get(f['severity'], f['severity'].capitalize())}"


def table(rows, cap=TABLE_CAP, accepted=False):
    head = "| Severity | Finding | Where | " + ("Reason | Expires |" if accepted else "Fix |")
    out = [head, "|" + "|".join(["---"] * (head.count("|") - 1)) + "|"]
    for f in rows[:cap]:
        cells = [sev(f), f"{ident(f)} {md(f.get('title'), 110)}", where(f)]
        if accepted:
            a = f.get("accepted") or {}
            cells += [md(a.get("reason"), 140), expiry(a.get("expires"))]
        else:
            cells.append(md(f.get("fix"), 120))
        out.append("| " + " | ".join(cells) + " |")
    if len(rows) > cap:
        out.append(f"\n…and {len(rows) - cap} more in `findings.json` in the `report-{env('CONTROL', '')}` artifact.")
    return "\n".join(out)


def expiry(date):
    if not date:
        return "no expiry (inline)"
    try:
        days = (dt.date.fromisoformat(date) - dt.date.today()).days
    except ValueError:
        return md(date)
    return f"{date} ⚠️ {days} days left" if days <= 30 else date


def version_key(v):
    return tuple((int(x), "") if x.isdigit() else (-1, x) for x in re.findall(r"\d+|[A-Za-z]+", v))


def upgrade_plan(blocking):
    """Per package: one version that fixes every listed advisory. Fix
    lists can name several release lines ("3.2.14, 4.0.6"): per advisory
    take its lowest fix above what's installed, then the highest of those."""
    plan = {}
    for f in blocking:
        if f.get("package") and f.get("fixed_version"):
            p = plan.setdefault((f["package"], f.get("version") or "", f.get("file") or f.get("where") or ""), {"fixes": [], "worst": f["severity"]})
            p["fixes"].append([x.strip() for x in f["fixed_version"].split(",") if x.strip()])
            p["worst"] = min(p["worst"], f["severity"], key=SEVERITIES.index)
    rows = []
    for (pkg, installed, loc), p in plan.items():
        firsts = [min((x for x in fx if version_key(x) > version_key(installed)), key=version_key, default=max(fx, key=version_key)) for fx in p["fixes"]]
        rows.append((SEVERITIES.index(p["worst"]), -len(firsts), pkg, installed, max(firsts, key=version_key), len(firsts), loc, p["worst"]))
    if not rows:
        return None
    rows.sort()
    out = [f"{len(rows)} package upgrade(s) clear every blocking finding that has a fix:", "",
           "| Package | Installed | Upgrade to (at least) | Fixes | Where |", "|---|---|---|---|---|"]
    for *_, pkg, installed, target, n, loc, worst in rows[:25]:
        out.append(f"| {ICON[worst]} `{md(pkg, 60)}` | {md(installed, 30)} | **{md(target, 30)}** | {n} | {md(loc, 60)} |")
    if len(rows) > 25:
        out.append(f"\n…and {len(rows) - 25} more packages in `findings.json`.")
    return "\n".join(out)


def counts(items):
    return {s: sum(f["status"] == s for f in items) for s in ("blocking", "reported", "accepted")}


def reproduce(control):
    """`make <control>` when the Makefile has that target (same pinned
    image, same arguments as this job)."""
    try:
        with open("Makefile") as f:
            if re.search(rf"^{re.escape(control)}:", f.read(), re.M):
                return f"make {control}"
    except OSError:
        pass
    return None


# --- per control -------------------------------------------------------------


def summary(control, out, items, kind, log=None):
    icon = {"pass": "✅", "fail": "❌", "skipped": "⏭️"}[out["status"]]
    n = counts(items)
    lines = [f"### {icon} {control}: {out['status']}" + (f" ({kind})" if out["status"] == "fail" else ""), ""]
    if out.get("tool"):
        lines.append(f"Tool: {md(out['tool'], 200)}  ")
    lines.append(md(out["detail"], 1000))
    if items:
        lines += ["", f"**{n['blocking']} blocking** · {n['reported']} reported, not blocking · {n['accepted']} accepted"]
    if out["status"] == "fail":
        lines += ["", f"> {KIND[kind]}"]
    if log and out["status"] == "fail":
        tail = "\n".join(log.strip().splitlines()[-25:]).replace("`" * 3, "` ` `")
        lines += ["", "Last lines of the tool's output:", "", "```text", tail, "```"]
    blocking = [f for f in items if f["status"] == "blocking"]
    plan = upgrade_plan(blocking)
    if plan:
        lines += ["", plan]
    native = env("NATIVE")
    if native and kind != "tool":
        lines += ["", f"The tool's own report is below (`{md(os.path.basename(native), 80)}`)"
                  + (", without the accepted risks." if n["accepted"] else ".")]
    elif blocking:
        lines += ["", "Blocking findings:", "", table(blocking)]
    for status, title in (("accepted", "Accepted risks"), ("reported", "Reported, not blocking")):
        if native and status == "reported":
            continue
        rows = [f for f in items if f["status"] == status]
        if rows:
            lines += ["", f"<details><summary>{title} ({len(rows)})</summary>", "", table(rows, accepted=status == "accepted"), "", "</details>"]
    cmd = reproduce(control)
    if cmd and out["status"] != "pass":
        lines += ["", f"Reproduce locally: `{cmd}` (same pinned image and arguments)."]
    return "\n".join(lines) + "\n\n"


def terminal(control, out, items):
    """Outside Actions (make): the blocking findings, one line each, unless
    the tool's own report follows."""
    if env("NATIVE"):
        return
    rows = [f for f in items if f["status"] == "blocking"]
    for f in rows[:25]:
        loc = f.get("file") and f"{f['file']}:{f.get('line') or ''}" or " ".join(filter(None, (f.get("package"), f.get("version")))) or f.get("where") or ""
        fix = f" → {f['fix']}" if f.get("fix") else ""
        print(f"  {f['severity'].upper():8} {f['id']}  {loc}  {f.get('title') or ''}{fix}"[:300])
    if len(rows) > 25:
        print(f"  …and {len(rows) - 25} more (findings.json)")


def sarif(control, tool, items):
    """File-anchored, not-accepted findings. Code scanning closes an alert
    when a later upload of the same category no longer has it."""
    anchored = [f for f in items if f.get("file") and f["status"] != "accepted"]
    rules = {}
    for f in anchored:
        rules.setdefault(f["id"], {
            "id": f["id"],
            "shortDescription": {"text": (f.get("title") or f["id"])[:200]},
            **({"helpUri": f["url"]} if f.get("url", "").startswith("https://") else {}),
            "properties": {"tags": ["security", control], "security-severity": SARIF_SCORE[f["severity"]]},
        })
    results = [{
        "ruleId": f["id"],
        "level": "error" if f["status"] == "blocking" else "warning" if f["severity"] in ("critical", "high", "unknown", "medium") else "note",
        "message": {"text": " ".join(filter(None, (f.get("title") or f["id"], f.get("package") and f"({f['package']} {f.get('version') or ''})".strip(), f.get("fix") and f"Fix: {f['fix']}")))[:1000]},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": max(1, int(f.get("line") or 1))}}}],
    } for f in anchored]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": control, "fullName": tool or control, "informationUri": "https://github.com/" + env("GITHUB_REPOSITORY", ""), "rules": list(rules.values())}},
                  "results": results}],
    }


def escape_data(s):
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_prop(s):
    return escape_data(s).replace(":", "%3A").replace(",", "%2C")


def annotations(control, items):
    anchored = [f for f in items if f["status"] == "blocking" and f.get("file")]
    for f in anchored[:ANNOTATION_CAP]:
        line = f",line={int(f['line'])}" if f.get("line") else ""
        msg = " ".join(filter(None, (f.get("title"), f.get("package") and f"({f['package']} {f.get('version') or ''})".strip(), f.get("fix") and f"Fix: {f['fix']}")))
        print(f"::error file={escape_prop(f['file'])}{line},title={escape_prop(control + ': ' + f['id'])}::{escape_data(msg[:500])}")
    if len(anchored) > ANNOTATION_CAP:
        print(f"::notice title={escape_prop(control)}::{len(anchored) - ANNOTATION_CAP} more blocking finding(s) with a location: see the job summary")


def publish(control, check, out, items, kind, folder, log=None):
    items = sorted(items, key=rank)
    for f in items:
        f["control"] = control
        f["key"] = key(f)
    n = counts(items)
    if folder:
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "findings.json"), "w") as fh:
            json.dump({"control": control, "check": check, "status": out["status"], "kind": kind if out["status"] == "fail" else None,
                       "tool": out.get("tool"), "counts": n, "findings": items}, fh, indent=1)
        # Written even with no results, so code scanning closes fixed alerts,
        # but not when the tool failed: an empty upload would close them too.
        if not (out["status"] == "fail" and kind == "tool"):
            with open(os.path.join(folder, "findings.sarif"), "w") as fh:
                json.dump(sarif(control, out.get("tool"), items), fh, indent=1)
        with open(os.path.join(folder, "accepted-ids.txt"), "w") as fh:
            fh.writelines(f"{i}\n" for i in sorted({f["id"] for f in items if f["status"] == "accepted"}))
    if env("GITHUB_STEP_SUMMARY"):
        with open(env("GITHUB_STEP_SUMMARY"), "a") as fh:
            fh.write(summary(control, out, items, kind, log))
    else:
        terminal(control, out, items)
    if env("GITHUB_ACTIONS"):
        annotations(control, items)


NATIVE_CAP = 200_000  # characters; a step summary can hold 1 MiB


def native(path, verdict_path=None):
    """Show a tool's own report: in full in the log, and in the job summary
    (capped; collapsed when the control passed). Markdown reports (.md) are
    embedded as they are, anything else as preformatted text."""
    try:
        with open(path, errors="replace") as fh:
            text = fh.read()
    except OSError:
        print(f"(no tool report at {path})")
        return
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    print(text)
    if not env("GITHUB_STEP_SUMMARY"):
        return
    status = None
    try:
        with open(verdict_path or os.path.join(os.path.dirname(path), "verdict.json")) as fh:
            status = json.load(fh).get("status")
    except (OSError, ValueError):
        pass
    name = os.path.basename(path)
    more = ""
    if len(text) > NATIVE_CAP:
        text = text[:NATIVE_CAP].rsplit("\n", 1)[0]
        more = f"\n\n…cut here; the full report is `{name}` in the `report-{env('CONTROL', '')}` artifact."
    if path.endswith(".md"):
        body = text.replace("<!--", "&lt;!--")
    else:
        body = "```text\n" + text.replace("`" * 3, "` ` `").rstrip() + "\n```"
    title = f"Tool report: {name}"
    block = (f"<details><summary>{title}</summary>\n\n{body}{more}\n\n</details>" if status == "pass"
             else f"#### {title}\n\n{body}{more}")
    with open(env("GITHUB_STEP_SUMMARY"), "a") as fh:
        fh.write(block + "\n\n")


# --- one PR comment for the whole run -----------------------------------------


MARKER = "<!-- devsecops-findings -->"


def read_reports(root):
    """{control: (verdict, findings-or-None)} from downloaded report-* dirs."""
    found = {}
    if not root or not os.path.isdir(root):
        return found
    for name in sorted(os.listdir(root)):
        folder = os.path.join(root, name)
        verdicts = [os.path.join(folder, v) for v in os.listdir(folder) if v == "verdict.json"] if os.path.isdir(folder) else []
        for path in verdicts:
            with open(path) as fh:
                verdict = json.load(fh)
            try:
                with open(os.path.join(folder, "findings.json")) as fh:
                    findings = json.load(fh)
            except (OSError, ValueError):
                findings = None
            found[verdict.get("control") or name.removeprefix("report-")] = (verdict, findings)
    return found


def read_gates(root):
    gates = {}
    if root and os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            m = re.fullmatch(r"gate-(?:result|preview)-(G\d)", name)
            path = os.path.join(root, name, "gate-result.json")
            if m and os.path.exists(path):
                with open(path) as fh:
                    gates[m.group(1)] = json.load(fh)
    return gates


def pr_comment(root, baseline_root=None):
    run_url = f"{env('GITHUB_SERVER_URL', 'https://github.com')}/{env('GITHUB_REPOSITORY', '')}/actions/runs/{env('GITHUB_RUN_ID', '')}"
    current, baseline = read_reports(root), read_reports(baseline_root)

    def keys(fs):
        return {f["key"] for f in fs["findings"] if f["status"] != "accepted"}

    # Compared per control, and only where main's run recorded findings for
    # it: no baseline for a control means "unknown", not "all new".
    base = {c: keys(fs) for c, (_, fs) in baseline.items() if fs}
    icon = {"pass": "✅", "fail": "❌", "skipped": "⏭️"}
    lines = [MARKER, f"## DevSecOps findings for {env('HEAD_SHA', '')[:7]}", ""]
    gates = read_gates(root)
    if gates:
        lines += [" · ".join(f"{icon.get(g.get('status'), '❔')} **{gid}** {g.get('status')}" for gid, g in sorted(gates.items())), ""]
    lines += ["| | Control | Blocking | New vs main | Detail |", "|---|---|---|---|---|"]
    new_blocking, fixed = [], []
    for control, (verdict, fs) in sorted(current.items(), key=lambda kv: (kv[1][0]["status"] != "fail", kv[0])):
        items = fs["findings"] if fs else []
        compared = fs is not None and control in base
        new = [f for f in items if f["status"] == "blocking" and f["key"] not in base[control]] if compared else []
        if compared:
            fixed += sorted(base[control] - keys(fs))
        new_blocking += new
        kind = f" ({fs['kind']})" if fs and fs.get("kind") else ""
        lines.append(f"| {icon.get(verdict['status'], '❔')} | {md(control, 40)}{kind} | {counts(items)['blocking'] if fs else '–'} | "
                     f"{len(new) if compared else '–'} | {md(verdict.get('detail'), 140)} |")
    if new_blocking:
        new_blocking.sort(key=rank)
        lines += ["", f"### New blocking findings in this PR ({len(new_blocking)})", "",
                  "| Control | Severity | Finding | Where | Fix |", "|---|---|---|---|---|"]
        for f in new_blocking[:30]:
            lines.append(f"| {md(f['control'], 40)} | {sev(f)} | {ident(f)} {md(f.get('title'), 90)} | {where(f)} | {md(f.get('fix'), 100)} |")
        if len(new_blocking) > 30:
            lines.append(f"\n…and {len(new_blocking) - 30} more: see the job summaries.")
    if fixed:
        lines += ["", f"<details><summary>Fixed compared with main ({len(fixed)})</summary>", ""]
        lines += [f"- `{md(k, 150)}`" for k in fixed[:50]] + ["", "</details>"]
    if base:
        lines += ["", f"_New vs main_ compares with the latest completed main run ({md(env('BASELINE_SHA', '')[:7] or '?')}): "
                  "the same finding means the same control, id and file or package (line numbers ignored). "
                  "– means main has no findings to compare with for that control._"]
    else:
        lines += ["", "_No main run with `findings.json` to compare with yet, so nothing is marked new._"]
    lines += ["", f"Full tables, fixes and reproduce commands are in each job's summary: [run {env('GITHUB_RUN_ID', '')}]({run_url}). "
              "Updated in place on every run."]
    body = "\n".join(lines)
    return body if len(body) < 60000 else body[:59000] + f"\n\n…truncated, see [the run]({run_url})."


if __name__ == "__main__":
    if sys.argv[1:2] == ["pr-comment"]:
        print(pr_comment(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None))
    elif sys.argv[1:2] == ["native"] and len(sys.argv) > 2:
        native(sys.argv[2])
    else:
        sys.exit("usage: findings.py pr-comment <reports-dir> [<baseline-dir>] | native <report-file>")
