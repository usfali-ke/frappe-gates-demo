"""End-to-end: the user journey through the real surfaces — log in, create a
note through the API, see it on the server-rendered page, close it, see the
page and the tally agree. This is the suite that would catch "the app works
but the page is broken", which the API-only suites cannot.

    BASE_URL=... USER_A=... PASSWORD_A=... pytest tests/live/test_e2e.py
"""

import pytest

from .client import BASE, CA, TIMEOUT, close, create, data, get, login, notes, stats, unique

pytestmark = pytest.mark.e2e


def _page(client):
	response = client.get(BASE + "/notes", timeout=TIMEOUT, verify=CA)
	assert response.status_code == 200, response.status_code
	return response.text


def test_journey_create_see_close(a):
	title = unique("e2e")
	before = stats(a)

	doc = create(a, title, severity="High", body="raised by the end-to-end suite")
	assert doc["status"] == "Open"

	page = _page(a)
	assert title in page, "the created note is not on the page"

	rows = {r["name"]: r for r in notes(a, limit=100)}
	assert rows[doc["name"]]["severity"] == "High"
	assert stats(a)["open"] == before["open"] + 1

	assert close(a, doc["name"])["status"] == "Closed"
	page = _page(a)
	assert title in page, "the closed note disappeared from the page"
	assert stats(a)["open"] == before["open"]


def test_the_page_shows_the_session_user_and_the_tally(a):
	page = _page(a)
	who = data(get(a, "whoami"))
	assert who["full_name"].split()[0] in page
	# The tally as notes.html words it since PR #16 ("Update header text"):
	# "<open> of <total> notes open". Checked against the API's own counts for
	# the same session, so the page is shown to agree with the data, not just
	# to contain a phrase.
	tally = stats(a)
	assert f"{tally['open']} of {tally['total']} notes open" in page, "the page's tally disagrees with notes_stats"


def test_the_api_and_the_page_agree_on_the_list(a):
	page = _page(a)
	for row in notes(a, limit=10):
		assert row["name"] in page, f"{row['name']} is listed by the API but not rendered"
