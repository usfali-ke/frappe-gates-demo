import os

import pytest

from .client import close, login, notes


@pytest.fixture(scope="session")
def user_a():
	return os.environ["USER_A"], os.environ["PASSWORD_A"]


@pytest.fixture(scope="session")
def user_b():
	return os.environ["USER_B"], os.environ["PASSWORD_B"]


@pytest.fixture(scope="module")
def a(user_a):
	s = login(*user_a)
	yield s
	_clean(s)


@pytest.fixture(scope="module")
def b(user_b):
	s = login(*user_b)
	yield s
	_clean(s)


def _clean(s):
	# The test users live as long as the site: leave it as we found it.
	for n in notes(s, limit=100):
		if n["status"] != "Open":
			continue
		try:
			close(s, n["name"])
		except AssertionError:
			pass  # already gone or closed by another suite; nothing to restore
