"""Post-deployment smoke tests: read-only, no test users, no writes, so they
are safe against prod (the release runs them right after prod's rollout;
dev's automated test suite runs them too).

    BASE_URL=https://app.test REQUESTS_CA_BUNDLE=ca.crt [HTTP_URL=http://app.test] pytest tests/live/test_smoke.py
"""

import pytest
import requests

from .client import API, BASE, CA, TIMEOUT, health

pytestmark = pytest.mark.smoke


def test_health_reports_the_app_and_its_database():
	r = health()
	assert r.status_code == 200, r.text[:300]
	payload = r.json()["message"]
	assert payload["status"] == "ok"
	assert payload["app"] == "frappe_gates_demo"
	assert payload["db"] is True
	assert payload["app_version"]
	assert payload["frappe_version"].startswith("15.")


def test_health_is_not_a_leak():
	"""The probe endpoint is guest-readable, so it must stay boring: no site
	path, no user, no configuration, no framework build details beyond the
	two versions."""
	payload = health().json()["message"]
	assert set(payload) == {"status", "app", "app_version", "frappe_version", "db"}
	assert "/home/" not in str(payload) and "sites" not in str(payload)


def test_login_page_renders():
	r = requests.get(BASE + "/login", timeout=TIMEOUT, verify=CA)
	assert r.status_code == 200
	assert 'data-page-route="login"' in r.text or "<title>Login</title>" in r.text


def test_root_answers():
	r = requests.get(BASE + "/", timeout=TIMEOUT, verify=CA)
	assert r.status_code in (200, 301, 302, 308), r.status_code


def test_guest_cannot_reach_the_notes_page():
	r = requests.get(BASE + "/notes", allow_redirects=False, timeout=TIMEOUT, verify=CA)
	assert r.status_code in (301, 302, 303, 307, 308), r.status_code
	assert "/login" in r.headers.get("Location", "")


def test_guest_api_calls_are_refused():
	for method in ("notes_list", "notes_stats"):
		r = requests.get(API + method, timeout=TIMEOUT, verify=CA)
		assert r.status_code == 403, f"{method}: {r.status_code}"
	r = requests.post(API + "note_create", json={"title": "guest"}, timeout=TIMEOUT, verify=CA)
	assert r.status_code == 403, r.status_code
