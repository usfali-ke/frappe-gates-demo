"""Gunicorn entry point: serve exactly one site, with its static assets.

Two things a bare `frappe.app:application` does not do, both needed when the
container is the whole web tier (no nginx in front):

* **Resolve the site.** Frappe picks the site from the request's Host header
  (``frappe/app.py``: ``_site or request.headers["X-Frappe-Site-Name"] or
  get_site_name(request.host)``) and 404s when no directory in ``sites/``
  matches. An image ships exactly one site and a cluster reaches it under many
  names — the pod IP the kubelet probes, the Service DNS the canary checks,
  ``localhost`` through a port-forward — so the site is pinned here.
  ``frappe.app._site`` is the same module-level switch ``bench serve --site``
  uses; it is set from SITE_NAME and never from the request.

* **Serve /assets and /files.** ``bench serve`` wraps the app in
  ``application_with_statics()``; without it every stylesheet and script 404s
  and the login page, the notes page and the desk all render unstyled. The
  assets are built into the image (``bench build`` in the Dockerfile), so this
  is static serving out of the image's ``sites/assets``.
"""

import os

import frappe.app

# gunicorn runs with --chdir=<bench>/sites, which is exactly the path Frappe
# expects (its own default is "."); only override it when asked.
SITES_PATH = os.path.abspath(os.environ.get("SITES_PATH") or os.getcwd())

frappe.app._site = os.environ.get("SITE_NAME") or "frappe-gates-demo.local"
frappe.app._sites_path = SITES_PATH
frappe.app.application_with_statics()

application = frappe.app.application
