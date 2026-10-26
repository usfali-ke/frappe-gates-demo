"""Build the run's evidence bundle from every control's report artifact.

    python3 .github/scripts/evidence.py <dir with report-*/ and gate-{result,preview}-*/> <out dir>

REPORT_PREFIX (default `report-`) is the artifact name prefix of the
reports: a release stage names them `report-<env>-<control>`, because one
release run deploys to dev, staging and prod and every environment runs
the same controls.

download-artifact extracts an artifact into its own folder only when a
pattern matches several; a lone gate artifact lands as <dir>/gate-result.json.
GATE_RECORDED ('true'/'false', default 'true') says whether that one was
uploaded as gate-result-* (recorded) or gate-preview-*.

Writes into <out dir>:
  manifest.json  what ran, what it decided, and the sha256 of every report
                 file — the predicate cosign attests to the image digest,
                 so the reports can be checked against it later;
  summary.md     the same as a table (also appended to the job summary);
  the report files themselves, under reports/<control>/.

A control with no report artifact, or no verdict.json in it, is listed as
`missing` — its job didn't get far enough to say anything.

`defectdojo` names the report file and DefectDojo scan type for import;
the security dashboard's collector reimports those (one test per control
per product, so a finding closed in code closes there too).
"""

import datetime as dt
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

# control → (stage, report file for DefectDojo or None, DefectDojo scan type)
CONTROLS = {
    "build": ("build", None, None),
    "unit-tests": ("develop", None, None),
    "coverage": ("test", None, None),
    "code-quality": ("develop", None, None),
    "sast-semgrep": ("develop", "semgrep.json", "Semgrep JSON Report"),
    "secrets-gitleaks": ("develop", "gitleaks.json", "Gitleaks Scan"),
    "secrets-trufflehog": ("develop", "trufflehog.jsonl", "Trufflehog Scan"),
    "sca-trivy": ("build", "trivy-fs.json", "Trivy Scan"),
    "iac-checkov": ("build", "checkov.json", "Checkov Scan"),
    "reviewers": ("develop", None, None),
    "commits-signed": ("develop", None, None),
    "ai-review": ("develop", None, None),
    "image-scan": ("build", "trivy.json", "Trivy Scan"),
    "sbom": ("build", "sbom.cdx.json", "CycloneDX Scan"),
    "image-compliance": ("build", "dockle.json", "Dockle Scan"),
    "frappe-migrate-check": ("build", None, None),
    "publish": ("build", None, None),
    # devsecops-stage.yml (one release stage per environment)
    "promotion": ("deliver", None, None),
    "provenance": ("deliver", None, None),
    "evidence-check": ("deliver", None, None),
    "config": ("deliver", "checkov/results_json.json", "Checkov Scan"),
    "previous-env-tests": ("deliver", None, None),
    "release-notes": ("release", None, None),
    "rollback-plan": ("release", None, None),
    "approve-prod": ("release", None, None),
    "deploy": ("deploy", None, None),
    "post-deploy": ("deploy", None, None),
    # against the deployed environment
    "smoke": ("test", None, None),
    "integration": ("test", None, None),
    "e2e": ("test", None, None),
    "regression": ("test", None, None),
    "security-tests": ("test", None, None),
    "performance": ("test", None, None),
    "dast-nuclei": ("test", "nuclei.jsonl", "Nuclei Scan"),
    "dast-tls": ("test", None, None),
    "dependency-check": ("test", "trivy.json", "Trivy Scan"),
    "health-watch": ("monitor", None, None),
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    e = os.environ.get
    applicable = [c for c in (e("CONTROLS") or ",".join(CONTROLS)).split(",") if c]
    prefix = e("REPORT_PREFIX") or "report-"
    (out / "reports").mkdir(parents=True, exist_ok=True)
    controls = []
    for name in applicable:
        stage, dd_file, dd_type = CONTROLS.get(name, ("?", None, None))
        folder = src / f"{prefix}{name}"
        entry = {"control": name, "stage": stage, "status": "missing", "detail": "no report — the job did not run (an earlier gate failed, or not applicable to this event) or crashed before uploading", "files": []}
        if folder.is_dir():
            dest = out / "reports" / name
            shutil.copytree(folder, dest, dirs_exist_ok=True)
            verdict_path = dest / "verdict.json"
            if verdict_path.is_file():
                v = json.loads(verdict_path.read_text())
                entry.update({k: v[k] for k in ("status", "detail", "tool", "metrics", "accepted") if k in v})
            else:
                entry["detail"] = "report artifact has no verdict.json (verdict step did not run)"
            entry["files"] = [
                {"path": str(p.relative_to(out)), "sha256": sha256(p), "bytes": p.stat().st_size}
                for p in sorted(dest.rglob("*")) if p.is_file()
            ]
            if dd_file and (dest / dd_file).is_file():
                entry["defectdojo"] = {"file": f"reports/{name}/{dd_file}", "scan_type": dd_type}
        controls.append(entry)

    gates = {}
    found = [(f / "gate-result.json", f.name.startswith("gate-result-")) for f in sorted(src.glob("gate-*-G*"))]
    found.append((src / "gate-result.json", (e("GATE_RECORDED") or "true") == "true"))
    for path, recorded in found:
        if path.is_file():
            g = json.loads(path.read_text())
            gates[g["gate"]] = {"status": g["status"], "recorded": recorded, "criteria": {c["key"]: c["status"] for c in g["criteria"]}}
            shutil.copy(path, out / f"gate-result-{g['gate']}.json")

    run_url = f"{e('GITHUB_SERVER_URL')}/{e('GITHUB_REPOSITORY')}/actions/runs/{e('GITHUB_RUN_ID')}"
    counts = {s: sum(c["status"] == s for c in controls) for s in ("pass", "fail", "skipped", "missing")}
    manifest = {
        "schema": "devsecops-evidence/v1",
        "repository": e("GITHUB_REPOSITORY"),
        "commit_sha": e("GITHUB_SHA"),
        "ref": e("GITHUB_REF"),
        "event": e("GITHUB_EVENT_NAME"),
        "run_url": run_url,
        "run_attempt": e("GITHUB_RUN_ATTEMPT"),
        "workflow": e("GITHUB_WORKFLOW_REF"),
        "artifact_digest": e("DIGEST") or None,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "result": "pass" if counts["fail"] == counts["missing"] == 0 else "fail",
        "counts": counts,
        "gates": gates,
        "controls": controls,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    icon = {"pass": "✅", "fail": "❌", "skipped": "⏭️", "missing": "⚠️"}
    lines = [
        f"## Evidence — {manifest['result']}",
        "",
        f"{counts['pass']} passed, {counts['fail']} failed, {counts['skipped']} skipped, {counts['missing']} missing · "
        f"commit `{(e('GITHUB_SHA') or '')[:7]}` · digest `{(e('DIGEST') or 'not built')[:19]}`",
        "",
        "Gates: " + (", ".join(f"**{g}** {v['status']}" for g, v in sorted(gates.items())) or "none evaluated in this run"),
        "",
        "| stage | control | status | tool | detail |",
        "|---|---|---|---|---|",
    ]
    for c in controls:
        detail = c["detail"].replace("|", "/").replace("\n", " ")
        lines.append(f"| {c['stage']} | `{c['control']}` | {icon[c['status']]} {c['status']} | {c.get('tool', '')} | {detail} |")
    lines += ["", "Every file above is hashed in `manifest.json`; on `main` the manifest is attested to the image digest (predicate type `https://github.com/%s/evidence/v1`)." % e("GITHUB_REPOSITORY", "")]
    summary = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(summary)
    if e("GITHUB_STEP_SUMMARY"):
        with open(e("GITHUB_STEP_SUMMARY"), "a") as f:
            f.write(summary)
    print(summary)


if __name__ == "__main__":
    main()
