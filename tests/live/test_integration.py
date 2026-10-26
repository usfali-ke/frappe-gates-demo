"""Integration tests against the deployed app: the app's own contract, with a
real session and a real database — create, read, filter, close, tally.

    BASE_URL=... USER_A=... PASSWORD_A=... pytest tests/live/test_integration.py
"""

import pytest

from .client import close, create, notes, stats, unique

pytestmark = pytest.mark.integration


def test_created_note_is_readable_and_owned_by_the_session(a):
	title = unique("integration")
	doc = create(a, title, severity="High", body="created by the integration suite")
	assert doc["status"] == "Open" and doc["severity"] == "High"

	rows = notes(a, limit=100)
	match = [r for r in rows if r["name"] == doc["name"]]
	assert match, f"{doc['name']} not in the list"
	row = match[0]
	assert row["title"] == title
	assert row["severity"] == "High"
	assert row["status"] == "Open"
	assert row["note_owner"] == a_user_of(a)
	assert row["age_days"] == 0


def test_list_is_newest_first(a):
	first = create(a, unique("order-first"), severity="Low")
	second = create(a, unique("order-second"), severity="Low")
	names = [r["name"] for r in notes(a, limit=100)]
	assert names.index(second["name"]) < names.index(first["name"])


def test_severity_filter_returns_only_that_severity(a):
	create(a, unique("filter-crit"), severity="Critical")
	rows = notes(a, severity="Critical", limit=100)
	assert rows and all(r["severity"] == "Critical" for r in rows)


def test_search_matches_title_and_body(a):
	token = unique("needle")
	doc = create(a, f"{token} in the title")
	create(a, unique("noise"), body=f"{token} in the body")
	found = {r["name"] for r in notes(a, search=token, limit=100)}
	assert doc["name"] in found
	assert len(found) >= 2


def test_limit_is_honoured(a):
	for _ in range(3):
		create(a, unique("limit"))
	assert len(notes(a, limit=2)) == 2


def test_closing_a_note_moves_it_out_of_the_open_tally(a):
	before = stats(a)
	doc = create(a, unique("closing"))
	mid = stats(a)
	assert mid["open"] == before["open"] + 1

	closed = close(a, doc["name"])
	assert closed["status"] == "Closed"
	after = stats(a)
	assert after["open"] == before["open"]
	assert after["total"] == mid["total"]


def test_stats_agree_with_the_list(a):
	s = stats(a)
	rows = notes(a, limit=100)
	assert s["total"] >= len(rows)
	assert s["total"] == sum(s["by_severity"].values())
	assert s["total"] == s["by_status"]["Open"] + s["by_status"]["Closed"]
	assert s["open"] == s["by_status"]["Open"]
	if s["highest_open_severity"]:
		assert s["by_severity"][s["highest_open_severity"]] > 0


def a_user_of(session):
	from .client import data, get

	return data(get(session, "whoami"))["user"]
