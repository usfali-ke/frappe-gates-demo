# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# The bench base image: Frappe v15 + node/yarn + built assets, no app.
#
# Why it exists separately: `bench init` clones the framework, resolves pip
# wheels and runs the asset build — none of that is byte-for-byte reproducible
# between two runs minutes apart (measured: two builds of the single-stage
# Dockerfile produced different digests). Publishing the bench once, pinned by
# digest, lets the app image be a COPY of source over a fixed base, which is
# reproducible by construction and takes seconds instead of minutes.
#
# Published by .github/workflows/bench-image.yaml to
#   ghcr.io/usfali-ke/frappe-gates-demo-bench:v15-<FRAPPE_VERSION>
# and referenced from the app Dockerfile BY DIGEST (never by tag).
FROM python:3.11-slim@sha256:b95327ce1439e687237841b0210677aeadd62d55a060a5f6bcb9c15bf6251dd3

ARG FRAPPE_VERSION=v15.123.1
ARG BENCH_VERSION=5.31.0
ARG NODE_MAJOR=18

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates curl git xz-utils gnupg build-essential libffi-dev pkg-config \
      cron procps mariadb-client \
 && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
 && apt-get install -y -qq --no-install-recommends nodejs \
 && npm install -g --silent "yarn@1.22.22" \
 && rm -rf /var/lib/apt/lists/* /root/.npm /usr/local/lib/node_modules/npm/cache

# Frappe bootstraps a new site by piping a schema dump through the mariadb CLI,
# and Debian's client requires TLS by default while the lab MariaDB serves
# plain TCP in-cluster. A real deployment keeps the TLS default.
RUN printf '[client]\nskip-ssl\n' > /etc/mysql/mariadb.conf.d/99-lab-no-tls.conf 2>/dev/null || \
    (mkdir -p /etc/mysql/mariadb.conf.d && printf '[client]\nskip-ssl\n' > /etc/mysql/mariadb.conf.d/99-lab-no-tls.conf)

RUN pip install "frappe-bench==${BENCH_VERSION}" \
 && groupadd -r -g 10001 frappe \
 && useradd -r -u 10001 -g 10001 -M -d /home/frappe -s /usr/sbin/nologin frappe \
 && mkdir -p /home/frappe

USER 10001:10001
WORKDIR /home/frappe
# Assets are built here (bench init runs `bench build`), so the app image never
# needs node.
RUN bench init \
      --frappe-branch "${FRAPPE_VERSION}" \
      --skip-redis-config-generation \
      --python python3.11 \
      frappe-bench \
 && find /home/frappe/frappe-bench/apps -name .git -prune -exec rm -rf {} + \
 && find /home/frappe/frappe-bench -name "__pycache__" -prune -exec rm -rf {} +

WORKDIR /home/frappe/frappe-bench
# One site ships in this image: the app image pins it in wsgi_site.py.
RUN printf 'frappe\n' > sites/apps.txt \
 && mkdir -p sites/assets logs

ENV HOME=/home/frappe \
    PYTHONPATH=/home/frappe/frappe-bench \
    PATH="/home/frappe/frappe-bench/env/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
