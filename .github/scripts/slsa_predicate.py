"""SLSA v1 provenance predicate for `cosign attest --type slsaprovenance1`,
built from the GitHub context the way GitHub's own generator shapes it.
devsecops-release.yml checks that resolvedDependencies names the released
commit."""

import json
import sys
import os

e = os.environ
repo_url = f"{e['GITHUB_SERVER_URL']}/{e['GITHUB_REPOSITORY']}"
json.dump(
    {
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {"workflow": {"ref": e["GITHUB_REF"], "repository": repo_url, "path": e["GITHUB_WORKFLOW_REF"].split("@", 1)[0].split("/", 2)[2]}},
            "internalParameters": {
                "github": {
                    "event_name": e["EVENT_NAME"],
                    "repository_id": e["REPO_ID"],
                    "repository_owner_id": e["OWNER_ID"],
                    "runner_environment": e["RUNNER_ENV"],
                }
            },
            "resolvedDependencies": [{"uri": f"git+{repo_url}@{e['GITHUB_REF']}", "digest": {"gitCommit": e["GITHUB_SHA"]}}],
        },
        "runDetails": {
            "builder": {"id": f"https://github.com/actions/runner/{e['RUNNER_ENV']}"},
            "metadata": {"invocationId": f"{repo_url}/actions/runs/{e['GITHUB_RUN_ID']}"},
        },
    },
    sys.stdout,
    indent=2,
)
