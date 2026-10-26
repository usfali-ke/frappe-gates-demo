"""Gunicorn entry point: serve exactly one site, whatever the Host header says.

Frappe resolves the site from the request's Host header (frappe/app.py:
``_site or request.headers["X-Frappe-Site-Name"] or get_site_name(request.host)``)
and 404s when no directory in ``sites/`` matches. A container image ships
exactly one site, and in a cluster it is reached under many names — the pod IP
the kubelet probes, the Service DNS the canary checks, ``localhost`` through a
port-forward — so pinning the site here is what makes the probes, the canary
and a browser all reach the app.

``frappe.app._site`` is the same module-level switch ``bench serve --site``
uses; it is set from SITE_NAME and never from the request.
"""

import os

import frappe.app

frappe.app._site = os.environ.get("SITE_NAME") or "frappe-gates-demo.local"
application = frappe.app.application
