#!/usr/bin/env python3
"""Push a pipeline run's scan reports straight to DefectDojo.

Runs in the `defectdojo-upload` workflow (workflow_run: completed) on the
in-cluster self-hosted runner, which can reach DefectDojo on the lab
network. Every report the run published as an artifact is reimported via
DefectDojo's /reimport-scan/ API, one Test per control:

  * an artifact with a manifest.json (`evidence`, `release-evidence-<env>`)
    names each control's report and DefectDojo scan type itself;
  * otherwise known tool reports are recognised by file name
    (semgrep.json, gitleaks.json, trivy-*.json, checkov results_json.json, ...).

Engagements:
  default branch (push / manual run)  -> "CI/CD"      (same as the dashboard collector)
  pull request                        -> "PR #<n>"    (never closes findings on main)
  any other branch                    -> "Branch <name>"

close_old_findings is on, scoped to the Test, so a finding fixed in code
closes in DefectDojo. Because of that, an older run is never allowed to
overwrite a Test that already holds a newer build (a re-run of an old
workflow would otherwise reopen what a newer scan closed).

Standard library only — no pip install on the runner.

Environment:
  DD_URL, DD_API_KEY, DD_PRODUCT          DefectDojo API root (…/api/v2), token, product name
  ARTIFACT_DIR                            artifacts, one sub-directory each (default ./artifacts)
  GITHUB_TOKEN, GITHUB_REPOSITORY         when set, the run's artifacts are downloaded into
                                          ARTIFACT_DIR first (scan reports only, see SKIP_ARTIFACTS)
  RUN_ID, RUN_ATTEMPT, RUN_URL, EVENT, HEAD_BRANCH, HEAD_SHA, DEFAULT_BRANCH, PR_NUMBER
  DRY_RUN=1                               print the plan, upload nothing
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import io
import time
import uuid
import zipfile
from pathlib import Path

# File name -> DefectDojo scan type, for artifacts without a manifest.
# Order matters: first match wins.
FILE_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^semgrep\.json$"), "Semgrep JSON Report"),
    (re.compile(r"^gitleaks\.json$"), "Gitleaks Scan"),
    (re.compile(r"^trufflehog\.jsonl?$"), "Trufflehog Scan"),
    (re.compile(r"^(results_json|checkov)\.json$"), "Checkov Scan"),
    (re.compile(r"^trivy[-\w]*\.json$"), "Trivy Scan"),
    (re.compile(r".*\.cdx\.json$|^sbom[-\w]*\.json$"), "CycloneDX Scan"),
    (re.compile(r"^nuclei\.jsonl$"), "Nuclei Scan"),
    (re.compile(r"^dockle\.json$"), "Dockle Scan"),
    (re.compile(r"^bandit\.json$"), "Bandit Scan"),
    (re.compile(r"^zap[-\w]*\.xml$"), "ZAP Scan"),
]
# Recognised but not importable as-is: say so instead of failing silently.
UNSUPPORTED = {
    re.compile(r"^zap[-\w]*\.json$"): "DefectDojo's ZAP parser only accepts XML — also write the report with `-x zap.xml`",
}
PREFIXES = ("evidence-", "report-", "scan-")
# Artifacts that never hold scan reports — the container image tarball
# alone is ~50 MB — and a size cap for anything else.
SKIP_ARTIFACTS = re.compile(r"^(image|gate-result.*|gate-preview.*|deployment-event.*|release-request)$")
MAX_ARTIFACT_BYTES = 50 * 1024 * 1024


def log(msg: str) -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    print(f"::warning::{msg}", flush=True)


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _http_url(url: str) -> str:
    """Refuse anything but http(s) — the artifact redirect's Location is chosen
    by the server, and a file://, ftp:// or data: URL must never be opened."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("https", "http"):
        raise ValueError(f"refusing non-HTTP(S) URL (scheme {scheme!r})")
    return url


def _opener(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    """A urllib opener with ONLY the HTTP(S) handlers (urlopen/build_opener
    would also install file://, ftp:// and data: handlers). `handlers`
    replace the default redirect handling."""
    opener = urllib.request.OpenerDirector()
    for h in (
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.UnknownHandler(),  # any other scheme raises URLError (else open() returns None)
        *(handlers or (urllib.request.HTTPRedirectHandler(),)),
    ):
        opener.add_handler(h)
    return opener


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_HTTP = _opener()
_HTTP_NO_REDIRECT = _opener(_NoRedirect())


def _github(url: str, token: str, *, raw: bool = False):
    req = urllib.request.Request(_http_url(url), headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    for attempt in range(4):
        try:
            if not raw:
                with _HTTP.open(req, timeout=60) as resp:
                    return json.loads(resp.read())
            # The zip download redirects to blob storage, which must NOT get
            # the GitHub token (urllib would forward it): follow it by hand.
            try:
                _HTTP_NO_REDIRECT.open(req, timeout=60)
                raise RuntimeError("expected a redirect to the artifact archive")
            except urllib.error.HTTPError as exc:
                if exc.code not in (301, 302, 303, 307, 308):
                    raise
                location = _http_url(exc.headers["Location"])
            with _HTTP.open(location, timeout=300) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == 3 or (isinstance(exc, urllib.error.HTTPError) and exc.code < 500 and exc.code != 429):
                raise
            time.sleep(2 ** attempt)


def download_artifacts(dest: Path) -> int:
    """Fetch the run's scan-report artifacts into dest/<artifact name>/."""
    token, repo, run = env("GITHUB_TOKEN"), env("GITHUB_REPOSITORY"), env("RUN_ID")
    api = env("GITHUB_API_URL", "https://api.github.com")
    listed, page = [], 1
    while True:
        batch = _github(f"{api}/repos/{repo}/actions/runs/{run}/artifacts?per_page=100&page={page}", token)["artifacts"]
        listed += batch
        if len(batch) < 100:
            break
        page += 1
    wanted = [a for a in listed if not a["expired"] and not SKIP_ARTIFACTS.match(a["name"]) and a["size_in_bytes"] <= MAX_ARTIFACT_BYTES]
    log(f"run {run}: {len(listed)} artifact(s), downloading {len(wanted)} that can hold scan reports")
    root = dest.resolve()
    for a in wanted:
        with zipfile.ZipFile(io.BytesIO(_github(a["archive_download_url"], token, raw=True))) as zf:
            target = (dest / a["name"]).resolve()
            for member in zf.namelist():
                out = (target / member).resolve()
                if root not in out.parents:  # zip-slip: never write outside dest
                    raise RuntimeError(f"artifact {a['name']} has an unsafe path: {member}")
            zf.extractall(target)
    return len(wanted)


def build_order(build_id: str | None) -> tuple[int, int] | None:
    """gh-<run id>-<attempt> -> (run id, attempt), for newer/older comparisons."""
    m = re.fullmatch(r"gh-(\d+)-(\d+)", build_id or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def pr_for_commit() -> str:
    """The PR a commit belongs to, when the run doesn't say. GitHub only
    attaches PR numbers to a workflow_run while the PR is open, so a PR merged
    before its pipeline finished arrives without one."""
    token, repo, sha = env("GITHUB_TOKEN"), env("GITHUB_REPOSITORY"), env("HEAD_SHA")
    if not (token and repo and sha):
        return ""
    try:
        pulls = _github(f"{env('GITHUB_API_URL', 'https://api.github.com')}/repos/{repo}/commits/{sha}/pulls", token)
        return str(pulls[0]["number"]) if pulls else ""
    except (urllib.error.URLError, KeyError, IndexError, ValueError):
        return ""


def engagement_name() -> str:
    event, branch, default = env("EVENT"), env("HEAD_BRANCH"), env("DEFAULT_BRANCH", "main")
    if event.startswith("pull_request"):
        pr = env("PR_NUMBER") or pr_for_commit()
        return f"PR #{pr}" if pr else f"Branch {branch}"
    return "CI/CD" if branch == default else f"Branch {branch}"


def plan(artifact_dir: Path) -> list[dict]:
    """Every (title, scan type, file) to import from this run."""
    uploads: list[dict] = []
    artifacts = sorted(p for p in artifact_dir.iterdir() if p.is_dir()) if artifact_dir.is_dir() else []
    manifested = False

    for art in artifacts:
        manifest = art / "manifest.json"
        if not manifest.is_file():
            continue
        try:
            controls = json.loads(manifest.read_text()).get("controls", [])
        except (json.JSONDecodeError, OSError) as exc:
            warn(f"{art.name}/manifest.json unreadable: {exc}")
            continue
        targets = [c for c in controls if (c.get("defectdojo") or {}).get("file")]
        if targets and not any((art / c["defectdojo"]["file"]).is_file() for c in targets):
            # A manifest that only references another artifact's reports
            # (e.g. an evidence-check job's verification copy), not a bundle.
            log(f"  {art.name}: manifest without its reports (a reference copy) — ignored")
            continue
        manifested = True
        # release-evidence-<env>: the same scan of dev and staging must not
        # close each other's findings, so the environment joins the title.
        environment = art.name.removeprefix("release-evidence-") if art.name.startswith("release-evidence-") else ""
        for control in controls:
            target = control.get("defectdojo") or {}
            if not target.get("scan_type") or control.get("status") == "missing":
                continue
            path = art / target["file"]
            if not path.is_file():
                warn(f"{art.name}: manifest names {target['file']} but it is not in the artifact")
                continue
            title = f"{control['control']}@{environment}" if environment else control["control"]
            uploads.append({"title": title, "scan_type": target["scan_type"], "path": path})

    for art in artifacts:
        if (art / "manifest.json").is_file():
            continue
        # A manifest already covers this run's per-control report artifacts.
        if manifested and art.name.startswith("report-"):
            continue
        base = art.name
        for prefix in PREFIXES:
            base = base.removeprefix(prefix)
        found = []
        for path in sorted(p for p in art.rglob("*") if p.is_file()):
            name = path.name
            for pattern, reason in UNSUPPORTED.items():
                if pattern.match(name):
                    warn(f"{art.name}/{name} skipped: {reason}")
            scan_type = next((t for pattern, t in FILE_RULES if pattern.match(name)), None)
            if scan_type:
                found.append((scan_type, path))
        for scan_type, path in found:
            title = base if len(found) == 1 else f"{base}-{path.stem}"
            if scan_type == "CycloneDX Scan" and "sbom" not in title.lower():
                title = f"sbom-{title}"  # the dashboard tells SBOM imports apart by "sbom" in the title
            uploads.append({"title": title, "scan_type": scan_type, "path": path})
    return uploads


class DefectDojo:
    def __init__(self, url: str, key: str) -> None:
        self.url = url.rstrip("/")
        self.headers = {"Authorization": f"Token {key}", "Accept": "application/json"}

    def _request(self, method: str, path: str, *, query: dict | None = None, body: bytes | None = None, ctype: str | None = None) -> dict:
        url = f"{self.url}{path}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        headers = dict(self.headers)
        if ctype:
            headers["Content-Type"] = ctype
        req = urllib.request.Request(_http_url(url), data=body, headers=headers, method=method)
        with _HTTP.open(req, timeout=120) as resp:
            return json.loads(resp.read() or b"{}")

    def get(self, path: str, **query: str) -> dict:
        return self._request("GET", path, query=query)

    def held_build(self, product: str, engagement: str, title: str) -> str | None:
        """build_id of the Test this upload would replace, if it exists."""
        products = self.get("/products/", name=product).get("results", [])
        if not products:
            return None
        engs = self.get("/engagements/", product=str(products[0]["id"]), name=engagement).get("results", [])
        if not engs:
            return None
        tests = self.get("/tests/", engagement=str(engs[0]["id"]), title=title).get("results", [])
        return tests[0].get("build_id") if tests else None

    def reimport(self, fields: dict[str, str], path: Path) -> dict:
        boundary = uuid.uuid4().hex
        parts = []
        for k, v in fields.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n".encode() + path.read_bytes() + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        return self._request("POST", "/reimport-scan/", body=b"".join(parts), ctype=f"multipart/form-data; boundary={boundary}")


def main() -> int:
    product = env("DD_PRODUCT")
    if not product:
        log("DD_PRODUCT (repo variable DEFECTDOJO_PRODUCT) is not set — nothing to do")
        return 0
    artifact_dir = Path(env("ARTIFACT_DIR", "artifacts"))
    if env("GITHUB_TOKEN") and env("GITHUB_REPOSITORY") and env("RUN_ID"):
        try:
            download_artifacts(artifact_dir)
        except (urllib.error.URLError, RuntimeError, zipfile.BadZipFile, KeyError) as exc:
            # Fail loudly: a run whose reports can't be fetched must not look uploaded.
            print(f"::error::Could not download the run's artifacts: {exc}", flush=True)
            return 1
    uploads = plan(artifact_dir)
    engagement = engagement_name()
    build_id = f"gh-{env('RUN_ID')}-{env('RUN_ATTEMPT', '1')}"
    log(f"{len(uploads)} report(s) -> DefectDojo product {product!r}, engagement {engagement!r}, build {build_id}")
    if not uploads:
        return 0
    if env("DRY_RUN") == "1":
        for u in uploads:
            log(f"  [dry run] {u['title']:<28} {u['scan_type']:<22} {u['path']}")
        return 0

    dd = DefectDojo(env("DD_URL"), env("DD_API_KEY"))
    this = build_order(build_id)
    summary = ["| Test | Scan type | Result |", "|---|---|---|"]
    failures = 0
    for u in uploads:
        title = u["title"]
        try:
            held = build_order(dd.held_build(product, engagement, title))
            if held and this and held > this:
                log(f"  skip {title}: DefectDojo already holds a newer build ({held[0]}-{held[1]})")
                summary.append(f"| {title} | {u['scan_type']} | skipped: newer build already imported |")
                continue
            result = dd.reimport(
                {
                    "scan_type": u["scan_type"],
                    "product_name": product,
                    "engagement_name": engagement,
                    "test_title": title,
                    "auto_create_context": "true",
                    "close_old_findings": "true",
                    "deduplication_on_engagement": "true",
                    "active": "true",
                    "verified": "false",
                    "build_id": build_id,
                    "commit_hash": env("HEAD_SHA"),
                    "branch_tag": env("HEAD_BRANCH"),
                    "source_code_management_uri": env("RUN_URL"),
                },
                u["path"],
            )
            stats = (result.get("statistics") or {}).get("after", {}).get("total", {})
            log(f"  imported {title} ({u['scan_type']}) -> test {result.get('test_id') or result.get('test')}")
            summary.append(f"| {title} | {u['scan_type']} | imported ({stats.get('active', '?')} active) |")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            if exc.code in (401, 403):
                print(f"::error::DefectDojo refused {title}: HTTP {exc.code} {detail}", flush=True)
                return 1  # credentials/permissions: every other upload would fail the same way
            warn(f"DefectDojo rejected {title} ({u['scan_type']}): HTTP {exc.code} {detail}")
            summary.append(f"| {title} | {u['scan_type']} | rejected: HTTP {exc.code} |")
            failures += 1
        except urllib.error.URLError as exc:
            print(f"::error::DefectDojo unreachable at {env('DD_URL')}: {exc.reason}", flush=True)
            return 1

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(f"### DefectDojo: {product} / {engagement}\n\n" + "\n".join(summary) + "\n")
    # One unparseable report shouldn't hide the others; it shows as a warning.
    log(f"done: {len(uploads) - failures} imported or current, {failures} rejected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
