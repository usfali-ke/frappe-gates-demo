# Frappe Gates Demo

A deliberately small **Frappe Framework v15 application** wired to the same
DevSecOps gate ladder as `django-gates-demo` and `flask-gates-demo`, so the
process can be exercised end to end on the framework our real products run
(Frappe `version-15` — ERPNext/HRMS/payments on `version-15`, as pinned in
`hmis-staging/.github/workflows/build-develop.yaml`).

Its purpose is not to be an application. Its purpose is to be the thing the
gates judge: a real framework, a real database, a real schema, a real image,
a real rollout, and evidence that reaches the security dashboard.

## What the app is

| Surface | What it does |
| --- | --- |
| DocType `Security Note` | the app's only domain object: title, severity (Low/Medium/High/Critical), status (Open/Closed), owner, body, pinned. Validation lives on the controller, not in the API. |
| `frappe_gates_demo.api.health` | guest-readable probe used by the Kubernetes probes, the canary AnalysisTemplate and the release's smoke suite. Reports app/frappe versions and whether the database answers — nothing else. |
| `frappe_gates_demo.api.notes_list`, `notes_stats`, `note_create`, `note_close`, `whoami` | the whitelisted API: permission-scoped through `frappe.get_list`, session-owned writes, validation refusals (417) and permission refusals (403). |
| `/notes` | a server-rendered page (the app's human surface): the list, the counts, the create form. |
| `frappe_gates_demo.install.after_install` | seeds one note, idempotently — an install hook the migration control actually exercises. |
| `frappe_gates_demo.test_support.ensure_user` | creates the two throwaway accounts the release's authenticated security suite needs (library, unit-tested). |
| `python -m frappe_gates_demo.ensure_user <email>` | the CLI the release runs inside the pod: the password arrives on stdin, is exported as `ENSURE_USER_PASSWORD` and read from the environment, never from argv. |

31 unit tests (Frappe's own runner, real MariaDB; 95% line coverage of the
app's own code) and 35 live tests (HTTP against the built image) cover it.
Both were run against the real artifact, not a stand-in.

## Layout

```
frappe_gates_demo/            the importable app (hooks, api, install, test_support)
  frappe_gates_demo/
    doctype/security_note/   doctype JSON + controller + unit tests
  tests/                     API / page / install unit tests
  www/notes.py, notes.html   the server-rendered page
.github/workflows/           the ported ladder: pipeline, release, stage, defectdojo-upload
.github/scripts/             gate.py (criteria map), verdict.py (control verdicts), evidence.py, ...
deploy/base|dev|staging|prod the GitOps overlays Argo CD syncs
tests/live/                  the environment suites (smoke, integration, e2e, regression, security)
tests/env/                   reach an environment through the TLS proxy, run one suite
tests/perf/load.js           k6 load profile
Dockerfile                   bench (pinned framework tag) + runtime
docker/entrypoint.sh         create site → install app → migrate → serve
```

## Run it locally

With a bench (the way the app is normally developed):

```bash
cd ~/frappe-bench
bench get-app /path/to/frappe-gates-demo
bench new-site fgd.local --db-root-password root --admin-password admin
bench --site fgd.local install-app frappe_gates_demo
bench --site fgd.local run-tests --app frappe_gates_demo      # 26 tests
bench --site fgd.local serve --port 8095
```

Without a bench, the same app in one command:

```bash
docker compose up --build      # mariadb + redis + the app
curl localhost:8000/api/method/frappe_gates_demo.api.health
```

The image's entrypoint creates the site, installs the app and migrates on
first start, so a fresh pod is a working site — the same idea as the Django
demo's migrate-on-start, with Frappe's three steps.

Lint (the pipeline's code-quality control): `make lint`
Coverage: `make coverage` (writes `reports/coverage/coverage.xml`).

## The pipeline

The files are the benchmark's (`django-gates-demo`), copied and adapted. What
runs:

* `devsecops-pipeline.yml` — CI. **Develop**: semgrep SAST, gitleaks +
  trufflehog, ruff, unit tests + coverage, PR reviewers, commit signatures, AI
  review → **G1 merge gate** → **Build**: image built twice and compared
  (reproducible), trivy SCA from `requirements.txt`, checkov on the Dockerfile
  and the rendered overlays, trivy on the image, syft SBOM, dockle, and the
  Frappe-specific control `frappe-migrate-check` (the image creates a site,
  installs the app and migrates against a real MariaDB — the equivalent of the
  Django demo's `manage.py check --deploy`) → **G2 fail-closed** →
  **Release**: evidence bundle, cosign attestation, hand-off to the release.
* `devsecops-release.yml` — one run chained dev → staging → prod, each a call
  into `devsecops-stage.yml`. Same jobs in every environment; prod adds
  exactly one: the `release-approval` review. No staging approval, no change
  request step (the benchmark removed both).
* `devsecops-stage.yml` — resolve the digest, GitOps commit, Argo CD sync, G5
  pre-deploy gates, deploy, post-deploy verification, then the per-environment
  Test phase (smoke/integration/e2e/regression/security/DAST/TLS/performance)
  and its test gate.
* gates G1…G7 with the criteria the dashboard's DoD catalogue expects; the
  mapping lives in `.github/scripts/gate.py`, one list, so a criterion cannot
  silently disappear.

### Deviations from `django-gates-demo` (declared, not accidental)

| Area | django-gates-demo | here | why |
| --- | --- | --- | --- |
| framework install | `uv sync` from `uv.lock` | `bench init` at the **tag** `v15.123.1`, `bench get-app` | Frappe is managed by bench; a tag (never a branch head) pins the framework source |
| unit tests | `pytest` + `pytest-django` | `bench --site … run-tests --app frappe_gates_demo` + `unittest-xml-reporting`; coverage.py wraps the runner | Frappe tests need a site, a database and app registration |
| deploy check | `manage.py check --deploy` | `bench migrate` inside the image | Frappe ships data (doctype JSON, patches); only a migration proves the artifact is complete |
| SCA input | `uv.lock` | `requirements.txt` (declares the framework version the app targets) | the app has no other third-party dependencies |
| runtime deps | gunicorn + one process | gunicorn + a MariaDB and a Redis beside it | a Frappe site is a database-backed application |
| state | SQLite in the pod | site directory on emptyDir, MariaDB StatefulSet, Redis | the site must survive a worker restart within the pod's life |
| probes | `/healthz` | `/api/method/frappe_gates_demo.api.health` | the app-owned probe, which also queries the database |

Everything else — the phase barriers, `record` vs preview, the approval
semantics, the evidence schema, the dashboard ingest — is identical; a change
to one demo repo's ladder should be a copy to the others.

## Where it shows up on the security dashboard

The product `frappe-gates-demo` is catalogued (`backend/seed/catalog.yaml`,
DefectDojo product 13) with its namespaces and repository, so:

* `GET /dod/overview?product=frappe-gates-demo` evaluates it against the DoD
  DevSecOps matrix (the same catalogue `/devsecops` and Compliance → DoD read),
  with every criterion that has no evidence reported as **missing with the
  reason** ("needs reproducible-build / SLSA provenance evidence from the
  pipeline", "no SCA scan in DefectDojo or from the pipeline", …) rather than
  guessed;
* `GET /org/checklist` / the Secure Build & Delivery page merge its pushed gate
  evaluations once the pipeline runs;
* runtime telemetry attributes to it through `k8s_namespaces`.

Before the first pipeline run the product therefore reads as *awaiting
evidence*. That is the honest state: nothing about this app has been built,
scanned, signed or deployed yet.

## Running the image (verified)

```bash
docker build -t frappe-gates-demo:local .
docker run -d --network fgd-net \
  -e DB_HOST=... -e DB_ROOT_PASSWORD=... -e SITE_NAME=frappe-gates-demo.local \
  -e REDIS_CACHE_URL=redis://.../0 -e REDIS_QUEUE_URL=redis://.../1 \
  frappe-gates-demo:local
curl localhost:8000/api/method/frappe_gates_demo.api.health   # {"status":"ok",...}
curl -o /dev/null -w '%{http_code}' localhost:8000/login       # 200
```

What the entrypoint does on first start, and why each step is there:

* waits for MariaDB, then `bench new-site --install-app` — the site is created
  *inside the container's copy of the bench*, not in a separate init job;
* writes the Redis URLs into the **site's** `site_config.json` (the site
  directory is the volume; the image-wide config stays read-only);
* creates `migrate` runs on every start, so a new image rolls the schema;
* `docker/wsgi.py` pins the site for gunicorn: Frappe otherwise resolves the
  site from the `Host` header and 404s for a pod IP or a Service DNS name.

Operational notes that cost real time here, worth keeping:

* **The site directory and the database are a pair.** `site_config.json` holds
  the site's DB credentials; an empty volume beside a live database cannot be
  recovered. The entrypoint refuses that state with an explicit message
  instead of Frappe's "Database ... already exists".
* **Frappe bootstraps a new site through the `mariadb` CLI.** Debian's client
  requires TLS by default, so the image ships a `[client] skip-ssl` drop-in
  (`/etc/mysql/mariadb.conf.d/99-lab-no-tls.cnf`). A real deployment keeps the
  default and provisions certificates.
* **`bench init` needs `crontab` and the runtime needs `git`**: bench's own
  config loading imports GitPython, and `getpass.getuser()` needs the runtime
  user in `/etc/passwd` (it is created with id 10001, the id the pod runs as).
* **Assets must be built** (`bench build`, which `bench init` runs): without
  `sites/assets/assets.json` the website pages and the desk render as 500s.
  `sites/` therefore stays image content — only `sites/<site>` is a volume.

## Not done yet (deliberately)

* No GitHub repository, no pipeline run, no cluster namespaces/Argo
  Applications: creating them is an infrastructure change that needs a
  decision, not a side effect of scaffolding.
* The rollout's read-only root filesystem was not exercised in this session
  (Docker could not give the mounted volumes the pod's uid). The mounts it
  needs — `sites/<site>`, `logs`, `/tmp` — are defined in
  `deploy/base/rollout.yaml`.

<!-- AI review e2e check: 2026-10-26T11:59:34Z -->

<!-- pipeline exercise 2026-10-26: AI review now ships the PR diff and retries a NOT COMPLETED answer -->

<!-- release ladder exercise 2026-10-27T06:49Z: site DB name + orphan drop -->
