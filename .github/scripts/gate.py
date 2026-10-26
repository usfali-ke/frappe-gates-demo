"""Assemble one gate decision from the control verdicts of this run.

Every control is its own job ending in verdict.py; a gate criterion is
answered by one or more of them (secrets = gitleaks + trufflehog). This file is the single list of which job answers which dashboard
criterion (keys: the dashboard's docs/GATE_INGEST_API.md).

    NEEDS='${{ toJSON(needs) }}' python3 .github/scripts/gate.py G1 out.json

NEEDS can also be a job's own `toJSON(steps)`: a step's outputs have the
same shape, so a job that runs several controls can name its verdict steps
after them. The pipelines don't: every control is its own job.
PROFILE picks another criteria list for the same gate (GATES["G3@staging"]).

A criterion is:
  fail     if any of its controls failed, or didn't leave a verdict (a
           crashed, cancelled or skipped job is never an implicit pass);
  skipped  if a control reported `skipped` (couldn't be evaluated in this
           context, e.g. no signature on a pull request) — not a pass;
  pass     only when every control passed.
The gate passes only when every criterion passes, except the keys in
ALLOW_SKIPPED (comma-separated) which may be `skipped` — used on pull
requests, where the image is built and tested but never published.

Writes gate-result.json (a GateEvaluationIn body), the job summary, and
`status=pass|fail` to $GITHUB_OUTPUT.
"""

import datetime as dt
import json
import os
import sys

# gate → [(criterion key, category, [(job id, output name)])]
_G5 = [
    ("artifact_provenance_verified", "security", [("provenance", "result"), ("evidence-check", "result")]),
    ("target_env_config_controlled", "delivery", [("config", "result")]),
    ("approved_gitops_pipeline_path", "governance", [("resolve", "promotion")]),
    # The digest to return to if this one fails: still signed and pullable.
    ("rollback_plan_ready", "delivery", [("rollback-plan", "result")]),
]

GATES = {
    "G1": [
        ("required_reviewers_approved", "governance", [("reviewers", "result")]),
        ("unit_tests_pass", "quality", [("unit-tests", "result")]),
        ("sast_clean", "security", [("sast-semgrep", "result")]),
        ("secrets_clean", "security", [("secrets-gitleaks", "result"), ("secrets-trufflehog", "result")]),
        ("commits_signed", "security", [("commits-signed", "result")]),
        ("ai_security_review_clean", "security", [("ai-review", "result")]),
    ],
    # The Control Gate at the end of CI (devsecops-pipeline.yml): build
    # successful, every static and image control clean, before anything is
    # deployed anywhere. Coverage and the image compliance checks are
    # properties of the artifact, so they are decided here, once, for the
    # digest. Doc mapping (docs/DevSecOps_process.docx): G2 is the BUILD
    # gate — reproducible build + no Critical/High + signed/attested + SBOM.
    # Unit tests and the coverage threshold are TEST-phase criteria: unit
    # tests are decided at G1 (the PR gate), coverage at G3 via the "G3@ci"
    # profile below, pushed by the same Control Gate job.
    "G2": [
        ("reproducible_build_config_controlled", "delivery", [("build", "result")]),
        ("code_quality_threshold_met", "quality", [("code-quality", "result")]),
        ("sast_clean", "security", [("sast-semgrep", "result")]),
        ("secrets_clean", "security", [("secrets-gitleaks", "result"), ("secrets-trufflehog", "result")]),
        ("sca_clean", "security", [("sca-trivy", "result")]),
        ("iac_clean", "security", [("iac-checkov", "result")]),
        ("container_image_scan_hardened_base", "security", [("image-scan", "result")]),
        ("compliance_scan_clean", "security", [("image-compliance", "result"), ("frappe-migrate-check", "result")]),
        ("artifact_signed_attested", "security", [("publish", "result")]),
        ("sbom_present", "security", [("sbom", "result")]),
    ],
    # The TEST phase's coverage criterion (doc G3: "...AND coverage
    # threshold met..."), decided in CI where coverage is measured — the
    # pipeline's Control Gate job records it as gate "G3" alongside G2, so
    # it merges with the G3 decisions the stage pipeline makes per
    # environment (functional, performance, DAST).
    "G3@ci": [
        ("coverage_threshold_met", "quality", [("unit-tests", "coverage")]),
    ],
    # G3 runs only against a deployed environment (devsecops-stage.yml, job
    # test-gate after one job per test), never against an image that isn't
    # deployed yet.
    # dev: smoke, integration and regression tests; DAST (nuclei, and the
    # authenticated security tests nuclei can't do); the deployed image's
    # dependencies re-scanned against today's vulnerability data.
    "G3@dev": [
        ("functional_integration_regression_pass", "quality",
         [("smoke", "result"), ("integration", "result"), ("regression", "result")]),
        ("dast_scan_clean", "security", [("dast-nuclei", "result"), ("security-tests", "result")]),
        ("dependency_check_clean", "security", [("dependency-check", "result")]),
    ],
    # staging: smoke, end-to-end and regression tests, performance, and the
    # security scans (nuclei, testssl.sh, authenticated).
    "G3@staging": [
        ("functional_integration_regression_pass", "quality",
         [("smoke", "result"), ("e2e", "result"), ("regression", "result")]),
        ("performance_within_slo", "quality", [("performance", "result")]),
        ("dast_scan_clean", "security",
         [("dast-nuclei", "result"), ("dast-tls", "result"), ("security-tests", "result")]),
    ],
    # prod after the rollout: read-only smoke tests (no test users, no
    # writes), then a health watch of the new pods. Argo CD's own G6 (sync,
    # canary analysis, admission) is recorded separately by the dashboard.
    "G6@prod": [
        ("post_deploy_smoke_pass", "quality", [("smoke", "result")]),
        ("post_deploy_health_watch_green", "delivery", [("health-watch", "result")]),
    ],
    # Before each environment's deploy commit (devsecops-stage.yml).
    "G5": _G5,
    "G5@dev": _G5,
    # Promotion into staging (dev and staging are otherwise the same
    # process): dev's G3 for this digest (test results + security scans) and
    # the release notes the reader of the run summary reads. No approval:
    # only prod has one.
    "G5@staging": _G5 + [
        ("previous_environment_tests_passed", "quality", [("previous-env-tests", "result")]),
        ("release_notes_published", "governance", [("release-notes", "result")]),
    ],
    # prod: the same criteria as staging plus its own approval — the
    # `release-approval` environment review (job approve-prod), by someone
    # who neither started the run nor authored the change. The dashboard
    # records its own G4 decision on the product's change record separately.
    "G5@prod": _G5 + [
        ("previous_environment_tests_passed", "quality", [("previous-env-tests", "result")]),
        ("release_notes_published", "governance", [("release-notes", "result")]),
        ("promotion_approved_by_other", "governance", [("approve-prod", "result")]),
    ],
}


def verdict(needs, job, output):
    j = needs.get(job) or {}
    try:
        v = json.loads((j.get("outputs") or {}).get(output) or "")
    except ValueError:
        v = None
    if not isinstance(v, dict) or v.get("status") not in ("pass", "fail", "skipped"):
        v = {"status": "fail", "detail": f"control did not complete ({job}: {j.get('result') or j.get('outcome') or 'not run'})"}
    return job, v


def criterion(needs, key, category, sources, evidence_url):
    parts = [verdict(needs, job, output) for job, output in sources]
    statuses = {v["status"] for _, v in parts}
    status = "fail" if "fail" in statuses else "skipped" if "skipped" in statuses else "pass"
    if len(parts) == 1:
        detail = parts[0][1].get("detail", "")
    else:
        detail = " | ".join(f"{job} {v['status']}: {v.get('detail', '')}" for job, v in parts)
    metrics = {}
    for job, v in parts:
        for name, value in (v.get("metrics") or {}).items():
            if isinstance(value, (int, float)):
                metrics[name if len(parts) == 1 else f"{job}.{name}"] = value
    out = {"key": key, "category": category, "status": status, "detail": detail[:1000], "evidence_url": evidence_url}
    if metrics:
        out["metrics"] = metrics
    return out


def main():
    gate, path = sys.argv[1], sys.argv[2]
    e = os.environ.get
    needs = json.loads(e("NEEDS") or "{}")
    run_url = f"{e('GITHUB_SERVER_URL')}/{e('GITHUB_REPOSITORY')}/actions/runs/{e('GITHUB_RUN_ID')}"
    allow_skipped = {k for k in (e("ALLOW_SKIPPED") or "").split(",") if k}
    # Every report is in the run's artifacts (report-<control>, and the
    # signed `evidence` bundle).
    profile = f"{gate}@{e('PROFILE')}" if e("PROFILE") else gate
    criteria = [criterion(needs, *c, evidence_url=f"{run_url}#artifacts") for c in GATES[profile]]
    ok = all(c["status"] == "pass" or (c["status"] == "skipped" and c["key"] in allow_skipped) for c in criteria)
    status = "pass" if ok else "fail"
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    body = {
        # product/source/run_url are overwritten by the dashboard from the
        # run it downloads this from; here so the file reads standalone.
        "product": e("PRODUCT") or e("GITHUB_REPOSITORY", "/").split("/")[-1],
        "gate": gate,
        "status": status,
        "source": "github-actions",
        "subject": e("SUBJECT"),
        "external_id": f"gh-{e('GITHUB_RUN_ID')}-{e('GITHUB_RUN_ATTEMPT')}-{gate}",
        "commit_sha": e("COMMIT_SHA") or e("GITHUB_SHA"),
        "artifact_digest": e("DIGEST") or None,
        "environment": e("ENVIRONMENT") or None,
        "run_url": run_url,
        "started_at": e("STARTED_AT") or now,
        "finished_at": now,
        "criteria": criteria,
    }
    with open(path, "w") as f:
        json.dump(body, f, indent=2)
    icon = {"pass": "✅", "fail": "❌", "skipped": "⏭️"}
    with open(e("GITHUB_STEP_SUMMARY"), "a") as f:
        f.write(f"### {gate}: {status}\n\n| | criterion | detail |\n|---|---|---|\n")
        f.write("".join(f"| {icon[c['status']]} {c['status']} | `{c['key']}` | {c['detail'].replace('|', '/')} |\n" for c in criteria))
        if allow_skipped:
            f.write(f"\n_Skipped allowed in this context: {', '.join(sorted(allow_skipped))}_\n")
    for c in criteria:
        print(f"{c['status']:>7}  {c['key']}: {c['detail']}")
    with open(e("GITHUB_OUTPUT"), "a") as f:
        f.write(f"status={status}\n")


if __name__ == "__main__":
    main()
