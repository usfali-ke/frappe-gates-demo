"""Regression tests: the rules the app promises to enforce, asserted over
HTTP against the deployed digest. A change that loosens validation (or that
turns a refusal into a 500) fails here, in the environment, before promotion.

Frappe answers a refused write with 417 Expectation Failed and an
`exc_type` of ValidationError; a refused read with 403.
"""

import pytest

from .client import call, create, get, notes, unique

pytestmark = pytest.mark.regression

MIN_TITLE = 3
MAX_TITLE = 140
MAX_BODY = 5000


def _expect_validation_error(response, message_fragment):
	assert response.status_code in (400, 417), response.status_code
	body = response.json()
	assert body.get("exc_type") in ("ValidationError", "MandatoryError"), body.get("exc_type")
	assert message_fragment in str(body), body.get("exception")


def test_a_blank_title_is_refused(a):
	_expect_validation_error(call(a, "note_create", title="   "), "Title must be at least")


def test_a_title_below_the_minimum_is_refused(a):
	_expect_validation_error(call(a, "note_create", title="a" * (MIN_TITLE - 1)), "Title must be at least")


def test_an_oversized_title_is_refused(a):
	_expect_validation_error(call(a, "note_create", title="a" * (MAX_TITLE + 1)), "at most")


def test_an_oversized_body_is_refused(a):
	_expect_validation_error(call(a, "note_create", title="Body too long", body="x" * (MAX_BODY + 1)), "at most")


def test_an_unknown_severity_is_refused_on_create(a):
	_expect_validation_error(call(a, "note_create", title="Bad severity", severity="Apocalyptic"), "severity")


def test_an_unknown_severity_is_refused_on_list(a):
	_expect_validation_error(get(a, "notes_list", severity="Nope"), "severity")


def test_an_unknown_status_filter_is_refused(a):
	_expect_validation_error(get(a, "notes_list", status="Archived"), "status")


def test_a_non_numeric_limit_is_refused(a):
	_expect_validation_error(get(a, "notes_list", limit="many"), "limit")


def test_the_title_is_trimmed_and_kept(a):
	title = unique("trimmed")
	doc = create(a, f"   {title}   ")
	assert doc["title"] == title


def test_the_limit_is_clamped_not_trusted(a):
	assert len(notes(a, limit=100000)) <= 100


def test_closing_an_unknown_note_is_refused(a):
	r = call(a, "note_close", name="SN-99999")
	assert r.status_code in (403, 404, 417), r.status_code
