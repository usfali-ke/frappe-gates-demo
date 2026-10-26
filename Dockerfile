# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
# DevSecOps demo app image: Frappe/ERPNext v15 (the version our product apps
# run) with this app installed.
#
# The bench (framework + node + built assets) is a SEPARATE image, pinned here
# BY DIGEST: docker/bench.Dockerfile, published by
# .github/workflows/bench-image.yaml. That separation is what makes this build
# reproducible — `bench init` resolves packages and builds assets at build
# time, and two runs of the single-stage Dockerfile produced two different
# digests (measured on the first pipeline run). With a fixed base, the only
# inputs here are this repository's source and two files the build writes,
# both deterministic.
FROM ghcr.io/usfali-ke/frappe-gates-demo-bench:v15-15.123.1@sha256:4ee7f5cc9f3cb66eef1710153c39122a46f85e5a92adc45a092ada451a90c1a2

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/home/frappe \
    PYTHONPATH=/home/frappe/frappe-bench \
    PATH="/home/frappe/frappe-bench/env/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

WORKDIR /home/frappe/frappe-bench
# COPY only, no RUN: the base image already registers the app (apps.txt, the
# import path) and holds the pristine sites/ template. A RUN here would stamp
# files with the build time, and the reproducible-build control compares the
# digests of the cached and --no-cache builds.
COPY --chown=10001:10001 . /home/frappe/frappe-bench/apps/frappe_gates_demo
COPY --chown=10001:10001 --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=10001:10001 docker/wsgi.py /home/frappe/frappe-bench/wsgi_site.py

# Numeric, so runAsNonRoot verifies it without an /etc/passwd entry (the base
# image creates uid 10001, so Frappe's getpass.getuser() still resolves).
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
