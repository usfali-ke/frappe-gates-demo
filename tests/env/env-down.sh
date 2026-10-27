#!/usr/bin/env bash
# Undoes tests/env/env-up.sh at the end of a test job, whatever happened:
# stops the port-forward and the proxy (its log goes into the report) and
# removes the file with the test users' passwords.
#
#     CONTROL=... TARGET_ENV=... bash tests/env/env-down.sh
set -uo pipefail
out="${OUT:-reports}/${CONTROL}"
proxy="env-proxy-${TARGET_ENV}-${CONTROL}"
mkdir -p "$out"
[ -f "$RUNNER_TEMP/port-forward.pid" ] && kill "$(cat "$RUNNER_TEMP/port-forward.pid")" 2>/dev/null
docker logs "$proxy" > "$out/proxy.log" 2>&1
docker rm -f "$proxy" > /dev/null 2>&1
rm -f "$RUNNER_TEMP/env-tests.env" "$RUNNER_TEMP/port-forward.pid"
exit 0
