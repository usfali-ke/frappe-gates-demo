"""HTTP helpers for the suites that run against a deployed environment.

Everything goes through the environment's TLS ingress (BASE_URL) the way a
browser or an integration would: Frappe session login, session cookie, and
the whitelisted app methods under /api/method/frappe_gates_demo.api.*.

Frappe wraps successful calls in {"message": ...}; a refusal is an HTTP
status (403 for permissions, 400/417 for validation) with an
{"exc_type": ...} body, so the suites assert on status codes first.
"""

import os
import uuid

import requests

BASE = os.environ["BASE_URL"].rstrip("/")
TIMEOUT = int(os.environ.get("TIMEOUT", "20"))
CA = os.environ.get("REQUESTS_CA_BUNDLE") or True
API = BASE + "/api/method/frappe_gates_demo.api."


def new_session():
	s = requests.Session()
	s.verify = CA
	return s


def login(user, password):
	"""Log in the way the web UI does and return the session."""
	s = new_session()
	r = s.post(BASE + "/api/method/login", data={"usr": user, "pwd": password}, timeout=TIMEOUT)
	assert r.status_code == 200, f"login for {user} failed: {r.status_code} {r.text[:200]}"
	assert r.json().get("message") == "Logged In", r.text[:200]
	return s


def get(s, method, **params):
	return s.get(API + method, params=params, timeout=TIMEOUT)


def call(s, method, **payload):
	return s.post(API + method, json=payload, timeout=TIMEOUT)


def data(response):
	assert response.status_code == 200, f"{response.status_code}: {response.text[:400]}"
	return response.json()["message"]


def create(s, title, severity="Medium", body=None):
	doc = data(call(s, "note_create", title=title, severity=severity, body=body))
	assert doc["name"].startswith("SN-"), doc
	return doc


def notes(s, **params):
	return data(get(s, "notes_list", **params))


def stats(s):
	return data(get(s, "notes_stats"))


def close(s, name):
	return data(call(s, "note_close", name=name))


def health():
	return requests.get(API + "health", timeout=TIMEOUT, verify=CA)


def unique(prefix):
	return f"{prefix}-{uuid.uuid4().hex[:10]}"
