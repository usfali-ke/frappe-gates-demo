"""Unit tests for the app's whitelisted API.

Run with: bench --site <site> run-tests --app frappe_gates_demo
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_gates_demo import __version__, api


class TestApi(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()

	def test_health_reports_app_and_database(self):
		payload = api.health()
		self.assertEqual(payload["status"], "ok")
		self.assertEqual(payload["app"], "frappe_gates_demo")
		self.assertEqual(payload["app_version"], __version__)
		self.assertTrue(payload["db"])
		self.assertIn("frappe_version", payload)

	def test_health_leaks_no_site_paths_or_users(self):
		payload = api.health()
		self.assertEqual(
			set(payload),
			{"status", "app", "app_version", "frappe_version", "db"},
		)

	def test_whoami_returns_roles_but_not_all_or_guest(self):
		payload = api.whoami()
		self.assertEqual(payload["user"], "Administrator")
		self.assertIn("System Manager", payload["roles"])
		self.assertNotIn("All", payload["roles"])
		self.assertNotIn("Guest", payload["roles"])

	def test_note_create_returns_the_new_note(self):
		created = api.note_create(title="Created through the API", severity="High")
		self.assertTrue(created["name"].startswith("SN-"))
		self.assertEqual(created["severity"], "High")
		self.assertEqual(created["status"], "Open")

	def test_note_create_defaults_severity_to_medium(self):
		created = api.note_create(title="Default severity")
		self.assertEqual(created["severity"], "Medium")

	def test_note_create_rejects_a_blank_title(self):
		with self.assertRaises(frappe.ValidationError):
			api.note_create(title="   ")

	def test_notes_list_is_newest_first_and_limited(self):
		for i in range(3):
			api.note_create(title=f"Listed note {i}", severity="Low")
		rows = api.notes_list(limit=2)
		self.assertEqual(len(rows), 2)
		self.assertIn("age_days", rows[0])

	def test_notes_list_filters_by_severity(self):
		api.note_create(title="Critical one", severity="Critical")
		api.note_create(title="Low one", severity="Low")
		rows = api.notes_list(severity="Critical")
		self.assertTrue(rows)
		self.assertTrue(all(row["severity"] == "Critical" for row in rows))

	def test_notes_list_rejects_an_unknown_severity(self):
		with self.assertRaises(frappe.ValidationError):
			api.notes_list(severity="Nope")

	def test_notes_list_clamps_the_limit(self):
		self.assertLessEqual(len(api.notes_list(limit=100000)), api.MAX_LIST_LIMIT)

	def test_notes_list_rejects_a_non_numeric_limit(self):
		with self.assertRaises(frappe.ValidationError):
			api.notes_list(limit="many")

	def test_note_close_moves_the_note_out_of_the_open_count(self):
		created = api.note_create(title="Close through the API")
		before = api.notes_stats()["by_status"]["Open"]
		api.note_close(name=created["name"])
		after = api.notes_stats()["by_status"]["Open"]
		self.assertEqual(after, before - 1)

	def test_notes_stats_totals_match_the_severity_breakdown(self):
		api.note_create(title="Stats critical", severity="Critical")
		api.note_create(title="Stats low", severity="Low")
		stats = api.notes_stats()
		self.assertEqual(stats["total"], sum(stats["by_severity"].values()))
		self.assertEqual(stats["total"], stats["by_status"]["Open"] + stats["by_status"]["Closed"])

	def test_guest_cannot_read_notes(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.PermissionError):
			api.notes_list()

	def test_guest_cannot_create_a_note(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.PermissionError):
			api.note_create(title="Guest note")
