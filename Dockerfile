# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# DevSecOps demo app image: Frappe/ERPNext v15 (the version our product apps
# run) with this app installed.
#
# Base refs are pinned by digest (the tag is informational); the pipeline's
# reproducible-build control fails on a floating FROM. FRAPPE_VERSION is a
# TAG, not a branch, so the same Dockerfile always installs the same framework
# source. The build is deterministic by construction: no lockfile resolution
# happens here (the app has no third-party dependencies), timestamps are
# rewritten by the exporter, and the git metadata `bench init` leaves behind
# is deleted — `.git` carries fetch times and would break digest equality
# between the cached and --no-cache builds.
FROM python:3.11-slim@sha256:b95327ce1439e687237841b0210677aeadd62d55a060a5f6bcb9c15bf6251dd3 AS bench

ARG FRAPPE_VERSION=v15.123.1
ARG BENCH_VERSION=5.31.0
ARG NODE_MAJOR=18

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# git + node are build-time needs (bench init clones the framework, asset
# building is Node). They are dropped from the runtime stage below.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates curl git xz-utils gnupg build-essential libffi-dev pkg-config \
      cron procps \
 && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
 && apt-get install -y -qq --no-install-recommends nodejs \
 && npm install -g --silent "yarn@1.22.22" \
 && rm -rf /var/lib/apt/lists/* /root/.npm /usr/local/lib/node_modules/npm/cache

RUN pip install "frappe-bench==${BENCH_VERSION}" \
 && useradd -m -u 10001 -s /bin/bash frappe

USER frappe
WORKDIR /home/frappe
RUN bench init \
      --frappe-branch "${FRAPPE_VERSION}" \
      --skip-redis-config-generation \
      --python python3.11 \
      frappe-bench \
 && find /home/frappe/frappe-bench/apps -name .git -prune -exec rm -rf {} + \
 && find /home/frappe/frappe-bench -name "__pycache__" -prune -exec rm -rf {} +

# --------------------------------------------------------------------------
FROM python:3.11-slim@sha256:b95327ce1439e687237841b0210677aeadd62d55a060a5f6bcb9c15bf6251dd3 AS runtime

# Runtime libraries only: the framework speaks MySQL over pymysql, and the
# bench CLI shells out to the mariadb client for a few administrative paths.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates git mariadb-client \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/log/apt-history.log
# Frappe bootstraps a new site by piping a schema dump through the mariadb
# CLI. Debian's client requires TLS by default while the lab MariaDB serves
# plain TCP in-cluster, so the bootstrap fails with "SSL is required, but the
# server does not support it". A real deployment keeps the TLS default and
# provisions certificates; this is a lab-wide exception, scoped to the client.
RUN printf '[client]\nskip-ssl\n' > /etc/mysql/mariadb.conf.d/99-lab-no-tls.cnf

# The runtime user must EXIST, not just have an id: bench's own config loading
# calls getpass.getuser(), which resolves uid 10001 through /etc/passwd and
# raises KeyError without this entry. HOME is the bench parent, as in a real
# bench install; it stays unwritable for the app (HOME=/tmp in the rollout).
RUN groupadd -r -g 10001 frappe \
 && useradd -r -u 10001 -g 10001 -M -d /home/frappe -s /usr/sbin/nologin frappe \
 && mkdir -p /home/frappe/frappe-bench

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/home/frappe \
    PYTHONPATH=/home/frappe/frappe-bench \
    PATH="/home/frappe/frappe-bench/env/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

COPY --from=bench --chown=10001:10001 /home/frappe/frappe-bench /home/frappe/frappe-bench
# bench and its resolver live in the BUILD stage's system Python. Copying the
# installed tree is byte-for-byte what that stage installed — re-running pip in
# the runtime stage would resolve again, and a pip index that moved between the
# two reproducible-build passes would break digest equality.
COPY --from=bench /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/
COPY --from=bench /usr/local/bin/bench /usr/local/bin/bench
COPY --from=bench /usr/local/bin/uv /usr/local/bin/uv
COPY --chown=10001:10001 . /home/frappe/frappe-bench/apps/frappe_gates_demo

WORKDIR /home/frappe/frappe-bench
# The app is registered the way `bench get-app` would (apps.txt + import path)
# without running pip: the app has no dependencies, and a pip call here would
# pull live index metadata into the layer and break reproducibility.
# The site directory is the writable volume, and a volume mounted at sites/
# HIDES this tree — including the built assets and apps.txt. Keep a pristine
# copy outside sites/ so the entrypoint can restore it into a fresh volume.
RUN printf 'frappe\nfrappe_gates_demo\n' > sites/apps.txt \
 && printf '/home/frappe/frappe-bench/apps/frappe\n/home/frappe/frappe-bench/apps/frappe_gates_demo\n' \
      > env/lib/python3.11/site-packages/frappe_apps.pth \
 && mkdir -p sites/assets logs \
 && cp -a sites /opt/sites-template \
 && chown -R 10001:10001 /opt/sites-template

COPY --chown=10001:10001 docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=10001:10001 docker/wsgi.py /home/frappe/frappe-bench/wsgi_site.py
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# Numeric, so runAsNonRoot verifies it without an /etc/passwd entry.
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/method/frappe_gates_demo.api.health', timeout=4)"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["gunicorn", \
     "--chdir=/home/frappe/frappe-bench/sites", \
     "--bind=0.0.0.0:8000", \
     "--threads=4", "--workers=2", "--worker-class=gthread", \
     "--worker-tmp-dir=/dev/shm", "--timeout=120", "--preload", \
     "wsgi_site:application"]
