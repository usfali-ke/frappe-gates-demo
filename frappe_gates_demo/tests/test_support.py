"""The test-support helper the release pipeline uses to create the two live
accounts. It is app code shipped in the image, so it is tested like app code:
creating, re-enabling and re-passwording a user, and the env-var contract that
keeps the password out of argv.
"""

import os

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_gates_demo import test_support

EMAIL = "gates-demo-support@example.test"


class TestSupport(FrappeTestCase):
	def tearDown(self):
		frappe.db.rollback()
		os.environ.pop("ENSURE_USER_PASSWORD", None)
		os.environ.pop("TEST_PROVISIONING_TOKEN", None)

	def test_ensure_user_creates_an_enabled_account_with_the_given_roles(self):
		test_support.ensure_user(EMAIL, "S3cret!pass", roles=("All",))
		self.assertTrue(frappe.db.exists("User", EMAIL))
		user = frappe.get_doc("User", EMAIL)
		self.assertEqual(user.enabled, 1)
		self.assertTrue(frappe.db.exists("Has Role", {"parent": EMAIL, "role": "All"}))

	def test_ensure_user_is_idempotent(self):
		test_support.ensure_user(EMAIL, "S3cret!pass")
		test_support.ensure_user(EMAIL, "An0ther!pass")
		self.assertEqual(frappe.db.count("User", {"email": EMAIL}), 1)
		self.assertEqual(frappe.get_doc("User", EMAIL).enabled, 1)

	def test_ensure_user_refuses_an_empty_password(self):
		with self.assertRaises(ValueError):
			test_support.ensure_user(EMAIL, "")

	def test_env_entry_point_requires_the_password_in_the_environment(self):
		with self.assertRaises(ValueError):
			test_support.ensure_user_from_env(EMAIL)

	def test_env_entry_point_creates_the_account(self):
		os.environ["ENSURE_USER_PASSWORD"] = "Fr0m!the-env"
		self.assertEqual(test_support.ensure_user_from_env(EMAIL), EMAIL)
		self.assertTrue(frappe.db.exists("User", EMAIL))


class TestProvision(FrappeTestCase):
	"""The pipeline's way to create the two live accounts without a shell in
	the pod: off without a token (prod), and narrow when on."""

	TOKEN = "t" * 43
	PASSWORD = "A-long-enough-pass!"

	def tearDown(self):
		frappe.db.rollback()
		os.environ.pop("TEST_PROVISIONING_TOKEN", None)

	def call(self, token, email=EMAIL, password=None):
		return test_support._provision(email, password or self.PASSWORD, token)

	def test_without_a_token_in_the_pod_it_does_not_exist(self):
		with self.assertRaises(frappe.DoesNotExistError):
			self.call(self.TOKEN)
		self.assertFalse(frappe.db.exists("User", EMAIL))

	def test_a_wrong_or_missing_token_is_refused(self):
		os.environ["TEST_PROVISIONING_TOKEN"] = self.TOKEN
		for token in ("", "t" * 42, "x" * 43):
			with self.assertRaises(frappe.PermissionError):
				self.call(token)
		self.assertFalse(frappe.db.exists("User", EMAIL))

	def test_only_test_accounts_with_a_long_password(self):
		os.environ["TEST_PROVISIONING_TOKEN"] = self.TOKEN
		for email in ("admin@example.com", "Administrator", "a@example.test.evil.com", ""):
			with self.assertRaises(frappe.ValidationError):
				self.call(self.TOKEN, email=email)
		with self.assertRaises(frappe.ValidationError):
			self.call(self.TOKEN, password="short")

	def test_with_the_token_it_creates_the_account(self):
		os.environ["TEST_PROVISIONING_TOKEN"] = self.TOKEN
		self.assertEqual(self.call(self.TOKEN), {"user": EMAIL})
		self.assertTrue(frappe.db.exists("Has Role", {"parent": EMAIL, "role": "Desk User"}))
