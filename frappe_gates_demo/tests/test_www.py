"""Unit tests for the server-rendered notes page's context builder.

The page itself is exercised end-to-end by tests/live (real HTTP, deployed
digest); this keeps its data path covered and proves the guest redirect.
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_gates_demo import api
from frappe_gates_demo.www import notes as notes_page


class TestNotesPage(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.local.flags.redirect_location = None
		frappe.db.rollback()

	def test_context_carries_notes_and_stats(self):
		api.note_create(title="Shown on the page", severity="High")
		context = frappe._dict()
		notes_page.get_context(context)
		self.assertEqual(context.title, "Security notes")
		self.assertEqual(context.user, "Administrator")
		self.assertTrue(any(n["title"] == "Shown on the page" for n in context.notes))
		self.assertGreaterEqual(context.stats["total"], len(context.notes))
		self.assertEqual(context.severities, api.SEVERITIES)

	def test_guest_is_redirected_to_login(self):
		frappe.set_user("Guest")
		with self.assertRaises(frappe.Redirect):
			notes_page.get_context(frappe._dict())
		self.assertTrue(frappe.local.flags.redirect_location.startswith("/login"))
