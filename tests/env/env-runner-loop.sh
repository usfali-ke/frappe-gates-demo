#!/usr/bin/env bash
# Keep one ephemeral GitHub Actions runner registered for this repo's
# `self-hosted, linux, frappe-gates-demo-env` jobs (the release pipeline's
# environment tests: smoke, integration, e2e, regression, security, DAST, TLS,
# performance, health watch).
#
# One registration serves one job, so this loops: register, run, re-register.
# The token is read from the dashboard's backend/.env when the UNIT STARTS, not
# per iteration — rotating GITHUB_TOKEN without restarting the unit leaves this
# loop failing with a bare `curl: (22) 401` every 5 s while the job sits queued.
# The pre-flight below turns that into one actionable line.
#
# Install as a systemd user unit, one instance per runner directory:
#   systemctl --user enable --now fgd-env-runner@b fgd-env-runner@c fgd-env-runner@d
set -uo pipefail

name="${1:?usage: env-runner-loop.sh <b|c|d|...>}"
env_file="${SDASH_ENV_FILE:-$HOME/Documents/work/security-dashboard/backend/.env}"
runner_dir="$HOME/actions-runner-fgd-$name"
repo_dir="${FGD_REPO_DIR:-$HOME/Documents/work/frappe-gates-demo}"

GH_TOKEN="$(grep -E '^GITHUB_TOKEN=' "$env_file" | cut -d= -f2-)"
if [ -z "$GH_TOKEN" ]; then
  echo "env-runner[$name]: GITHUB_TOKEN is missing from $env_file" >&2
  exit 1
fi
export GH_TOKEN

while :; do
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${GH_TOKEN}" \
    https://api.github.com/user 2>/dev/null || echo 000)"
  if [ "$code" != "200" ]; then
    echo "env-runner[$name]: GitHub rejected GITHUB_TOKEN (HTTP $code) — rotate it in $env_file," \
      "then restart the fgd-env-runner units so every consumer picks it up" >&2
    sleep 15
    continue
  fi

  # A stale .runner/.credentials from a killed job makes registration fail.
  rm -f "$runner_dir/.runner" "$runner_dir/.credentials" "$runner_dir/.credentials_rsaparams"
  (cd "$repo_dir" && bash tests/env/env-runner.sh "$runner_dir") || sleep 5
done
