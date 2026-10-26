#!/usr/bin/env bash
# Container entrypoint: make the site exist, make the app installed, then run.
#
# A Frappe deployment is not a stateless WSGI app: it needs a site directory, a
# database that already carries the framework schema, and the app installed on
# that site. Doing that here (idempotently, on every start) keeps the image a
# single artifact the pipeline can sign and the cluster can roll — the same
# shape as the Django demo's migrate-on-start, with Frappe's three steps.
set -euo pipefail

BENCH_DIR="${BENCH_DIR:-/home/frappe/frappe-bench}"
SITE_NAME="${SITE_NAME:-frappe-gates-demo.local}"
DB_HOST="${DB_HOST:-mariadb}"
DB_PORT="${DB_PORT:-3306}"
DB_ROOT_USER="${DB_ROOT_USER:-root}"
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
APP="${APP:-frappe_gates_demo}"

if [ -z "$DB_ROOT_PASSWORD" ]; then
	echo "entrypoint: DB_ROOT_PASSWORD is required" >&2
	exit 1
fi

cd "$BENCH_DIR"

# Redis: one instance, three logical databases (cache / queue / socketio).
bench set-config -g redis_cache "${REDIS_CACHE_URL:-redis://redis:6379/0}" >/dev/null
bench set-config -g redis_queue "${REDIS_QUEUE_URL:-redis://redis:6379/1}" >/dev/null
bench set-config -g redis_socketio "${REDIS_SOCKETIO_URL:-redis://redis:6379/2}" >/dev/null
bench set-config -g developer_mode 0 >/dev/null

echo "entrypoint: waiting for ${DB_HOST}:${DB_PORT}"
python - "$DB_HOST" "$DB_PORT" "$DB_ROOT_USER" "$DB_ROOT_PASSWORD" <<'PY'
import sys
import time

import pymysql

host, port, user, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
deadline = time.time() + 120
while True:
    try:
        pymysql.connect(host=host, port=port, user=user, password=password, connect_timeout=3).close()
        print("entrypoint: database is up")
        break
    except Exception as exc:  # noqa: BLE001 - any connection error means "not yet"
        if time.time() > deadline:
            raise SystemExit(f"entrypoint: database unreachable after 120s: {exc}") from exc
        time.sleep(2)
PY

if [ ! -d "sites/${SITE_NAME}" ]; then
	echo "entrypoint: creating site ${SITE_NAME}"
	# --no-mariadb-socket: pymysql over TCP, so the image needs no socket path.
	bench new-site "$SITE_NAME" \
		--db-host "$DB_HOST" --db-port "$DB_PORT" \
		--mariadb-root-username "$DB_ROOT_USER" \
		--mariadb-root-password "$DB_ROOT_PASSWORD" \
		--admin-password "$ADMIN_PASSWORD" \
		--no-mariadb-socket \
		--install-app "$APP" \
		--set-default
else
	if ! bench --site "$SITE_NAME" list-apps | grep -qx "$APP"; then
		echo "entrypoint: installing ${APP} on ${SITE_NAME}"
		bench --site "$SITE_NAME" install-app "$APP"
	fi
	bench --site "$SITE_NAME" migrate
fi

echo "entrypoint: starting: $*"
exec "$@"
