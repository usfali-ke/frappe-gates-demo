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
# The database name is DERIVED, not Frappe's default: without --db-name Frappe
# invents _<hash>, which the orphan check below cannot see, so a second pod
# (fresh emptyDir, same MariaDB) reused a database whose user it had just given
# a new password — "Access denied for user _fb8d00a034cf6693". Same rule as the
# check, applied in one place.
DB_NAME="$(printf '%s' "$SITE_NAME" | tr -c '0-9a-zA-Z' '_' | tr 'A-Z' 'a-z')"

if [ -z "$DB_ROOT_PASSWORD" ]; then
	echo "entrypoint: DB_ROOT_PASSWORD is required" >&2
	exit 1
fi

cd "$BENCH_DIR"

# A fresh volume mounted at sites/ is empty: restore the parts that ship with
# the image (built assets, assets.json, apps.txt, the site-wide config) before
# anything else runs. -n: never overwrite what the volume already holds.
if [ ! -f sites/assets/assets.json ] && [ -d /home/frappe/sites-template ]; then
	echo "entrypoint: seeding sites/ from the image template"
	mkdir -p sites
	cp -an /home/frappe/sites-template/. sites/
fi

# Redis and the site's switches come from the environment, never from a write
# to sites/common_site_config.json: the image keeps that file read-only (the
# root filesystem is read-only in the cluster), and Frappe reads the
# FRAPPE_REDIS_* variables in preference to the config file.
export FRAPPE_REDIS_CACHE="${REDIS_CACHE_URL:-redis://redis:6379/0}"
export FRAPPE_REDIS_QUEUE="${REDIS_QUEUE_URL:-redis://redis:6379/1}"
export FRAPPE_REDIS_SOCKETIO="${REDIS_SOCKETIO_URL:-redis://redis:6379/2}"

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

# The site directory and the database are a PAIR: site_config.json is the only
# place the site's database credentials live. An empty volume beside a live
# database cannot be recovered by guessing, so say so plainly instead of
# letting Frappe fail with "Database ... already exists".
if [ ! -f "sites/${SITE_NAME}/site_config.json" ]; then
	if python - "$SITE_NAME" "$DB_HOST" "$DB_PORT" "$DB_ROOT_USER" "$DB_ROOT_PASSWORD" <<'PY'
import re
import sys

import pymysql

site, host, port, user, password = sys.argv[1:6]
db = re.sub(r"[^0-9a-zA-Z]+", "_", site).lower()
try:
    conn = pymysql.connect(host=host, port=int(port), user=user, password=password, connect_timeout=5)
except Exception:
    raise SystemExit(0)
with conn.cursor() as cur:
    cur.execute("SHOW DATABASES LIKE %s", (db,))
    raise SystemExit(0 if cur.fetchone() else 1)
PY
	then
		# The site directory is the pod's own emptyDir, so a database with this
		# name can only be an orphan from a previous pod (the same MariaDB
		# persists across pods). Frappe names such a database _<hash> unless
		# --db-name is given, which is why the guard above never saw it and the
		# next pod died with "Access denied for user _fb8d00a034cf6693" — it
		# generated a fresh password for a user the old pod had created.
		# Drop the orphan and bootstrap cleanly.
		echo "entrypoint: database ${DB_NAME} exists without a site (orphan from a previous pod); dropping it"
		MYSQL_PWD="$DB_ROOT_PASSWORD" mariadb --host "$DB_HOST" --port "$DB_PORT" \
			--user "$DB_ROOT_USER" --skip-ssl \
			-e "DROP DATABASE IF EXISTS \`${DB_NAME}\`" || {
			echo "entrypoint: could not drop ${DB_NAME}" >&2
			exit 1
		}
	fi
	# A volume mounted at the site path makes Docker/Kubernetes create the
	# directory itself; Frappe's new-site refuses an existing directory even
	# when it is empty. rmdir (not rm -rf) keeps this safe: a directory that
	# holds anything at all stays put.
	rmdir "sites/${SITE_NAME}" 2>/dev/null || true
	echo "entrypoint: creating site ${SITE_NAME}"
	# --no-mariadb-socket: pymysql over TCP, so the image needs no socket path.
	bench new-site "$SITE_NAME" \
		--db-name "$DB_NAME" \
		--db-host "$DB_HOST" --db-port "$DB_PORT" \
		--mariadb-root-username "$DB_ROOT_USER" \
		--mariadb-root-password "$DB_ROOT_PASSWORD" \
		--mariadb-user-host-login-scope='%' \
		--admin-password "$ADMIN_PASSWORD" \
		--install-app "$APP"
else
	if ! bench --site "$SITE_NAME" list-apps | grep -qx "$APP"; then
		echo "entrypoint: installing ${APP} on ${SITE_NAME}"
		bench --site "$SITE_NAME" install-app "$APP"
	fi
	bench --site "$SITE_NAME" migrate
fi

# Redis lives in the SITE's config (writable), not in the image-wide one: the
# site directory is the volume, and everything that reads the site config —
# the web workers, `bench` commands, the test-support CLI — must agree.
bench --site "$SITE_NAME" set-config redis_cache "${REDIS_CACHE_URL:-redis://redis:6379/0}" >/dev/null
bench --site "$SITE_NAME" set-config redis_queue "${REDIS_QUEUE_URL:-redis://redis:6379/1}" >/dev/null
bench --site "$SITE_NAME" set-config redis_socketio "${REDIS_SOCKETIO_URL:-redis://redis:6379/2}" >/dev/null

# A cache that outlives the build serves the PREVIOUS image's asset hashes:
# `assets_json` holds the bundle filenames, and when the same Redis is reused
# across deploys the page requests /assets/...<old-hash>.css, gets 404 and
# renders unstyled (measured: the page asked for 357ROE7P while this image had
# built EN2VUT6E). Clear it at boot so the hashes always come from the files
# this container actually ships. Cheap and idempotent; every deploy has a cold
# cache anyway.
bench --site "$SITE_NAME" clear-cache >/dev/null

echo "entrypoint: starting: $*"
exec "$@"
