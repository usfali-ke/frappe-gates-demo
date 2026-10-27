#!/usr/bin/env bash
# Makes the deployed environment reachable for one test job on the
# environment test runner (README: "Environment test runner"):
#
#     NS=... DIGEST=... TARGET_ENV=... CONTROL=... CADDY=... [TEST_USERS=true] bash tests/env/env-up.sh
#
# - finds a ready pod in $NS running $DIGEST (the pod under test must run
#   the released digest) and port-forwards to it;
# - with TEST_USERS=true (never in prod), creates two random-password users
#   on THAT SITE through the app's own helper (frappe_gates_demo.test_support),
#   the password on stdin, never in argv; named after the control, so test
#   jobs don't share them;
# - starts the Caddy TLS proxy (tests/env/Caddyfile) in front of it.
#
# Ports are per environment and control, so test jobs on runners sharing
# a host don't collide. Writes BASE_URL, HTTP_URL and the CA files to
# $GITHUB_ENV, and everything incl. the passwords to the 0600 file
# $RUNNER_TEMP/env-tests.env. tests/env/env-down.sh undoes it.
set -euo pipefail

controls=(smoke integration e2e regression security-tests performance dast-nuclei dast-tls health-watch)
envs=(dev staging prod)
i=-1; e=-1
for n in "${!controls[@]}"; do [ "${controls[$n]}" != "$CONTROL" ] || i=$n; done
for n in "${!envs[@]}"; do [ "${envs[$n]}" != "$TARGET_ENV" ] || e=$n; done
[ "$i" -ge 0 ] && [ "$e" -ge 0 ] || { echo "::error::no ports for ${CONTROL} in ${TARGET_ENV}"; exit 1; }
o=$((e * 20 + i))
APP_PORT=$((18000 + o)); HTTP_PORT=$((18100 + o)); HTTPS_PORT=$((18200 + o))
proxy="env-proxy-${TARGET_ENV}-${CONTROL}"
out="${OUT:-reports}/${CONTROL}"
mkdir -p "$out"

pods=$(kubectl -n "$NS" get pods -l app=frappe-gates-demo -o json)
pod=$(jq -r --arg d "$DIGEST" '[.items[] | select(.status.phase == "Running")
       | select(any((.status.containerStatuses // [])[]; .ready and (.imageID | endswith($d))))][0].metadata.name // empty' <<<"$pods")
[ -n "$pod" ] || { echo "::error::no ready pod in ${NS} runs ${DIGEST}"; jq -r '.items[] | "\(.metadata.name) \(.status.containerStatuses[0].imageID)"' <<<"$pods"; exit 1; }
echo "Testing pod ${pod} (${DIGEST:0:19}…) in ${NS} on https://localhost:${HTTPS_PORT}" | tee -a "$GITHUB_STEP_SUMMARY"
nohup kubectl -n "$NS" port-forward "pod/${pod}" "${APP_PORT}:8000" > "$out/port-forward.log" 2>&1 &
echo $! > "$RUNNER_TEMP/port-forward.pid"

rand() { python3 -c 'import secrets; print(secrets.token_urlsafe(24))'; }
env_file="$RUNNER_TEMP/env-tests.env"
(umask 077; {
  echo "BASE_URL=https://localhost:${HTTPS_PORT}"; echo "HTTP_URL=http://localhost:${HTTP_PORT}"
  echo "REQUESTS_CA_BUNDLE=$RUNNER_TEMP/env-bundle.crt"
  echo "SSL_CERT_FILE=$RUNNER_TEMP/env-bundle.crt"
  if [ "${TEST_USERS:-}" = true ] && [ "$TARGET_ENV" != prod ]; then
    echo "USER_A=${TARGET_ENV}-${CONTROL}-alice@example.test"; echo "PASSWORD_A=$(rand)"
    echo "USER_B=${TARGET_ENV}-${CONTROL}-bob@example.test"; echo "PASSWORD_B=$(rand)"
  fi; } > "$env_file")
set -a
# shellcheck source=/dev/null
. "$env_file"
set +a
if [ -n "${USER_A:-}" ]; then
  for u in A B; do
    user="USER_$u"; pw="PASSWORD_$u"
    # The password travels on stdin and is exported inside the pod: the app's
    # helper reads ENSURE_USER_PASSWORD, so it never reaches argv or ps.
    printf '%s\n' "${!pw}" | kubectl -n "$NS" exec -i "$pod" -- bash -c '
      read -r ENSURE_USER_PASSWORD; export ENSURE_USER_PASSWORD
      cd /home/frappe/frappe-bench
      exec ./env/bin/python -m frappe_gates_demo.ensure_user "$0"' "${!user}"
  done
fi

# A proxy left by a cancelled job would hold the ports.
docker rm -f "$proxy" > /dev/null 2>&1 || true
# caddy carries a file capability (cap_net_bind_service): without it in
# the bounding set the binary can't even exec. A 0644 copy of the
# Caddyfile: the checkout's modes follow the runner's umask, and root in a
# cap-drop ALL container can't read past them.
install -m 644 tests/env/Caddyfile "$RUNNER_TEMP/Caddyfile"
docker run -d --name "$proxy" --network host --cap-drop ALL --cap-add NET_BIND_SERVICE \
  -e APP_PORT="$APP_PORT" -e HTTP_PORT="$HTTP_PORT" -e HTTPS_PORT="$HTTPS_PORT" \
  -v "$RUNNER_TEMP/Caddyfile:/etc/caddy/Caddyfile:ro" "$CADDY" > /dev/null
for _ in $(seq 30); do
  docker cp "${proxy}:/data/caddy/pki/authorities/local/root.crt" "$RUNNER_TEMP/env-ca.crt" 2>/dev/null \
    && curl -fsS --cacert "$RUNNER_TEMP/env-ca.crt" -o /dev/null "${BASE_URL}/api/method/frappe_gates_demo.api.health" && break
  sleep 2
done
curl -fsS --cacert "$RUNNER_TEMP/env-ca.crt" -o /dev/null "${BASE_URL}/api/method/frappe_gates_demo.api.health" \
  || { docker logs "$proxy" 2>&1 | tail -20; tail -5 "$out/port-forward.log"; exit 1; }
cat /etc/ssl/certs/ca-certificates.crt "$RUNNER_TEMP/env-ca.crt" > "$RUNNER_TEMP/env-bundle.crt"
chmod 644 "$RUNNER_TEMP/env-ca.crt" "$RUNNER_TEMP/env-bundle.crt"   # read by tool containers running as other uids
{ echo "BASE_URL=${BASE_URL}"; echo "HTTP_URL=${HTTP_URL}"; echo "ENV_PROXY=${proxy}"
  echo "ENV_CA=$RUNNER_TEMP/env-ca.crt"; echo "ENV_FILE=${env_file}"; } >> "$GITHUB_ENV"
