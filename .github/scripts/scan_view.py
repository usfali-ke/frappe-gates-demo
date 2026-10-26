"""Render-for-scanning: reads `kustomize build deploy/<env>` on stdin and
writes the same manifests with each Argo Rollout re-expressed as a
Deployment carrying the identical pod template. Checkov and Trivy only
evaluate native workload kinds, so without this the Rollout — the one
object that actually runs the image — would be silently skipped and the
scan would pass vacuously. The rewritten file is only scanned, never
applied."""
import sys

import yaml

docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
rollouts = 0
for d in docs:
    if d.get("kind") == "Rollout" and d.get("apiVersion", "").startswith("argoproj.io/"):
        d["apiVersion"], d["kind"] = "apps/v1", "Deployment"
        d["spec"].pop("strategy", None)
        d["spec"].pop("workloadRef", None)
        rollouts += 1
if not rollouts:
    sys.exit("no Rollout in the render — refusing to produce a scan view without the workload")
yaml.safe_dump_all(docs, sys.stdout, sort_keys=False)
