"""Authenticated security tests (DAST, with two real users): what an
unauthenticated scanner (nuclei) can't reach — object-level authorization
across accounts, the session's life cycle, injection, and what responses
give away. OWASP Top 10 2021 category in each docstring.

    BASE_URL=... USER_A=... PASSWORD_A=... USER_B=... PASSWORD_B=... REQUESTS_CA_BUNDLE=... \\
    pytest tests/live/test_security.py
"""

import pytest

from .client import API, BASE, CA, TIMEOUT, call, close, create, data, get, login, notes, unique

pytestmark = pytest.mark.security


def test_idor_a_note_is_invisible_to_another_user(a, b):
	"""A01: B's list never carries A's note, and B cannot close it."""
	doc = create(a, unique("private"))
	assert doc["name"] not in [r["name"] for r in notes(b, limit=100)]

	r = call(b, "note_close", name=doc["name"])
	assert r.status_code == 403, f"B closed A's note: {r.status_code} {r.text[:200]}"

	still_open = {r["name"]: r["status"] for r in notes(a, limit=100)}
	assert still_open.get(doc["name"]) == "Open"


def test_idor_the_page_does_not_leak_another_users_note(a, b):
	"""A01: the server-rendered list is scoped to the session too."""
	doc = create(a, unique("page-private"))
	page = b.get(BASE + "/notes", timeout=TIMEOUT, verify=CA)
	assert page.status_code == 200
	assert doc["name"] not in page.text
	assert data(get(a, "whoami"))["user"] != data(get(b, "whoami"))["user"]


def test_cross_site_script_in_a_title_is_escaped_on_the_page(a):
	"""A03: the page renders note text escaped — a stored payload must not
	become executable markup."""
	payload = "<script>alert(1)</script>"
	doc = create(a, payload)
	page = a.get(BASE + "/notes", timeout=TIMEOUT, verify=CA)
	assert page.status_code == 200
	assert payload not in page.text, "the raw script tag was rendered"
	assert doc["name"] in page.text


def test_sql_metacharacters_in_a_search_are_data_not_syntax(a):
	"""A03: filters are parameterized — a quote/marker payload must neither
	500 nor widen the result set."""
	token = unique("sqli")
	doc = create(a, token)
	for probe in ("'; drop table tabSecurity Note; --", "%' or '1'='1", f"{token}' OR 1=1 --"):
		r = get(a, "notes_list", search=probe, limit=100)
		assert r.status_code == 200, f"{probe!r} -> {r.status_code}"
	assert doc["name"] in {r["name"] for r in notes(a, search=token, limit=100)}


def test_logout_ends_the_session(user_a):
	"""A07: the session actually dies — a logged-out cookie is a guest."""
	client = login(*user_a)
	doc = create(client, unique("session"))
	assert doc["name"]
	client.post(BASE + "/api/method/logout", timeout=TIMEOUT, verify=CA)
	r = client.get(API + "notes_list", timeout=TIMEOUT, verify=CA)
	assert r.status_code == 403, f"logged-out session still read notes: {r.status_code}"


def test_session_cookie_is_not_script_readable(user_a):
	"""A07: the session cookie carries HttpOnly."""
	import requests

	s = requests.Session()
	s.verify = CA
	r = s.post(BASE + "/api/method/login",
	           data={"usr": user_a[0], "pwd": user_a[1]},
	           timeout=TIMEOUT)
	raw = "; ".join(r.raw.headers.getlist("Set-Cookie"))
	assert "sid=" in raw and "HttpOnly" in raw, raw


def test_a_second_user_cannot_see_the_first_users_tally(a, b):
	"""A01: the counts are permission-scoped, not global."""
	before_b = data(get(b, "notes_stats"))["total"]
	create(a, unique("tally"), severity="Critical")
	after_b = data(get(b, "notes_stats"))["total"]
	assert after_b == before_b, "B's tally moved when A created a note"


def test_closing_is_idempotent_for_the_owner(a):
	doc = create(a, unique("idempotent"))
	assert close(a, doc["name"])["status"] == "Closed"
	assert close(a, doc["name"])["status"] == "Closed"
