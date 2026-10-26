"""Unit tests for the Security Note DocType controller.

Run with: bench --site <site> run-tests --app frappe_gates_demo
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_gates_demo.frappe_gates_demo.doctype.security_note.security_note import (
	MAX_BODY,
	MIN_TITLE,
)


class TestSecurityNote(FrappeTestCase):
	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()

	def _make(self, **kwargs):
		values = {"doctype": "Security Note", "title": "A note", "severity": "Medium"}
		values.update(kwargs)
		doc = frappe.get_doc(values)
		doc.insert()
		return doc

	def test_insert_defaults_owner_and_status(self):
		doc = self._make(title="Defaulted fields")
		self.assertEqual(doc.note_owner, "Administrator")
		self.assertEqual(doc.status, "Open")
		self.assertTrue(doc.name.startswith("SN-"))

	def test_owner_cannot_be_spoofed_on_insert(self):
		doc = self._make(title="Spoofed owner", note_owner="Guest")
		self.assertEqual(doc.note_owner, "Administrator")

	def test_title_is_trimmed(self):
		doc = self._make(title="   padded title   ")
		self.assertEqual(doc.title, "padded title")

	def test_short_title_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			self._make(title="a" * (MIN_TITLE - 1))

	def test_unknown_severity_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			self._make(title="Bad severity", severity="Apocalyptic")

	def test_oversized_body_is_rejected(self):
		with self.assertRaises(frappe.ValidationError):
			self._make(title="Too long", body="x" * (MAX_BODY + 1))

	def test_body_at_limit_is_accepted(self):
		doc = self._make(title="At the limit", body="x" * MAX_BODY)
		self.assertEqual(len(doc.body), MAX_BODY)

	def test_closed_status_survives_an_edit(self):
		doc = self._make(title="Close me")
		doc.status = "Closed"
		doc.save()
		doc.reload()
		doc.title = "Closed note, edited"
		doc.save()
		doc.reload()
		self.assertEqual(doc.status, "Closed")
