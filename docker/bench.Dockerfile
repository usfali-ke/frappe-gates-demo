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

# The pango/glib/cairo set is what WeasyPrint needs to render PDFs (frappe
# print formats). Without it `import weasyprint` fails with "cannot load
# library libgobject-2.0-0" — measured on the previous base image, so PDF
# export was broken there, not by the dependency upgrade.
# libglib2.0-0 is `libglib2.0-0t64` on Debian 13.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates curl git xz-utils gnupg build-essential libffi-dev pkg-config \
      cron procps mariadb-client \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libglib2.0-0t64 \
      libcairo2 libjpeg62-turbo libopenjp2-7 libxslt1.1 libxml2 \
      fontconfig fonts-dejavu-core \
 && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
 && apt-get install -y -qq --no-install-recommends nodejs \
 && npm install -g --silent "yarn@1.22.22" \
 && rm -rf /var/lib/apt/lists/* /root/.npm /usr/local/lib/node_modules/npm/cache

# Frappe bootstraps a new site by piping a schema dump through the mariadb CLI,
# and Debian's client requires TLS by default while the lab MariaDB serves
# plain TCP in-cluster. A real deployment keeps the TLS default.
# NOTE the .cnf suffix: MariaDB's `!includedir` only takes files that end in
# .cnf, and a `[client] skip-ssl` in a .conf name is silently ignored (measured:
# the client then fails with "SSL is required, but the server does not support
# it" while `mariadb --skip-ssl` on the same command line works).
RUN mkdir -p /etc/mysql/mariadb.conf.d \
 && printf '[client]\nskip-ssl\n' > /etc/mysql/mariadb.conf.d/99-lab-no-tls.cnf

RUN pip install "frappe-bench==${BENCH_VERSION}" \
 && groupadd -r -g 10001 frappe \
 && useradd -r -u 10001 -g 10001 -M -d /home/frappe -s /usr/sbin/nologin frappe \
 && mkdir -p /home/frappe \
 # bench init creates <HOME>/frappe-bench as this uid, so HOME must be its own.
 && chown 10001:10001 /home/frappe

USER 10001:10001
WORKDIR /home/frappe
# Assets are built here (bench init runs `bench build`), so nothing below is
# needed at runtime — and this is where the image scan's 1248 Critical/High
# came from: 1071 were `stdlib` (the Go runtime inside Node/esbuild binaries)
# plus npm packages (postcss, brace-expansion, minimatch, loader-utils) that
# only exist to BUILD the bundles. `bench build` already wrote sites/assets,
# so the toolchain and the module trees are dropped. The app image therefore
# ships a runtime, not a build machine. (Verified: bench migrate and gunicorn
# serve the site with node absent.)
RUN bench init \
      --frappe-branch "${FRAPPE_VERSION}" \
      --skip-redis-config-generation \
      --python python3.11 \
      frappe-bench \
 && find /home/frappe/frappe-bench -type d -name node_modules -prune -exec rm -rf {} + \
 && find /home/frappe/frappe-bench/apps -name .git -prune -exec rm -rf {} + \
 && find /home/frappe/frappe-bench -name "__pycache__" -prune -exec rm -rf {} + \
 && rm -rf /home/frappe/.cache /home/frappe/.npm /home/frappe/.yarn /home/frappe/.esbuild

# Frappe 15.123.1 pins several libraries below the release that fixes their
# published advisories: Pillow~=12.3.0 (28 findings, fixed in 13.0.0),
# pypdf==6.15.0 (11), PyJWT~=2.13.0 (7, one Critical), GitPython~=3.1.34 (2),
# WeasyPrint==69.0 (1). Bumping the framework instead of the pins is the
# upstream-correct fix, but the 15.x tags still pin Pillow 12.3 and
# GitPython 3.1, so the image cannot be clean AND stay on the framework's own
# pins. These are therefore installed with --no-deps at the fixed versions,
# and the app is exercised against them (migrate, API, notes page) rather than
# assumed compatible. setuptools is bumped because it VENDORS jaraco.context
# and wheel, and the vendored copies were the last two findings.
USER 10001:10001
WORKDIR /home/frappe/frappe-bench
RUN env/bin/pip install --no-cache-dir -q --no-deps --upgrade \
      "GitPython==3.2.1" "PyJWT==2.15.1" "pillow==13.0.0" "pypdf==6.21.2" \
      "urllib3==2.8.0" "filelock==4.2.1" "msgpack==1.2.1" "weasyprint==70.0" \
      "setuptools==84.2.1" "wheel==0.46.3" "jaraco.context==6.1.0" "uv==0.13.4"

# The bench CLI itself lives in the system interpreter, so the same fixes are
# applied there — trivy scans every Python environment in the image, and a fix
# in one of them is not a fix.
USER root
RUN /usr/local/bin/pip install --no-cache-dir -q --no-deps --upgrade \
      "GitPython==3.2.1" "PyJWT==2.15.1" "pillow==13.0.0" "pypdf==6.21.2" \
      "urllib3==2.8.0" "filelock==4.2.1" "msgpack==1.2.1" "weasyprint==70.0" \
      "setuptools==84.2.1" "wheel==0.46.3" "jaraco.context==6.1.0" "uv==0.13.4" \
 && rm -rf /root/.cache/pip

# pip is a build tool and vendors its own copies of msgpack/urllib3 — the last
# findings in the image were pip's `_vendor` tree, not anything the app can
# import. Nothing at runtime installs packages (the entrypoint only runs
# new-site/install-app/migrate and gunicorn), so pip and its metadata are
# removed from both interpreters. Re-enable by adding `python -m ensurepip` in
# the app image if a future step needs to install at runtime.
USER root
RUN rm -rf /usr/local/lib/python3.11/site-packages/pip \
           /usr/local/lib/python3.11/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.11 \
           /home/frappe/frappe-bench/env/lib/python3.11/site-packages/pip \
           /home/frappe/frappe-bench/env/lib/python3.11/site-packages/pip-*.dist-info \
           /home/frappe/frappe-bench/env/bin/pip \
           /home/frappe/frappe-bench/env/bin/pip3 /home/frappe/frappe-bench/env/bin/pip3.11

# node/yarn/npm are build-only. Purged as root: the packages were installed by
# apt and npm, and removing the binaries also removes esbuild's Go runtime and
# the npm toolchain's own dependency tree from the scanned filesystem.
USER root
RUN apt-get purge -y nodejs >/dev/null \
 && apt-get autoremove -y >/dev/null \
 && rm -rf /usr/lib/node_modules /usr/local/lib/node_modules /usr/local/share/.cache/yarn \
           /root/.npm /root/.cache /home/frappe/.cache \
           /usr/bin/node /usr/bin/yarn /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
USER 10001:10001
WORKDIR /home/frappe/frappe-bench
# The app's registration and the pristine copy of sites/ live HERE, not in the
# app image: every RUN layer in the app image is a chance for a timestamp to
# differ between the cached and --no-cache builds (the reproducible-build
# control compares image digests), so the app image is COPY-only.
RUN printf 'frappe\nfrappe_gates_demo\n' > sites/apps.txt \
 && printf '/home/frappe/frappe-bench/apps/frappe\n/home/frappe/frappe-bench/apps/frappe_gates_demo\n' \
      > env/lib/python3.11/site-packages/frappe_apps.pth \
 && mkdir -p sites/assets logs \
 && cp -a sites /home/frappe/sites-template

ENV HOME=/home/frappe \
    PYTHONPATH=/home/frappe/frappe-bench \
    PATH="/home/frappe/frappe-bench/env/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
