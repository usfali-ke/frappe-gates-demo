import frappe
from frappe import _
from frappe.model.document import Document

SEVERITIES = ("Low", "Medium", "High", "Critical")
MAX_BODY = 5000
MIN_TITLE = 3


class SecurityNote(Document):
	def validate(self):
		self.title = (self.title or "").strip()
		if len(self.title) < MIN_TITLE:
			frappe.throw(
				_("Title must be at least {0} characters").format(MIN_TITLE),
				frappe.ValidationError,
			)
		if len(self.title) > 140:
			frappe.throw(_("Title must be at most 140 characters"), frappe.ValidationError)
		if self.severity not in SEVERITIES:
			frappe.throw(_("Unknown severity {0}").format(self.severity), frappe.ValidationError)
		if self.body and len(self.body) > MAX_BODY:
			frappe.throw(
				_("Body must be at most {0} characters").format(MAX_BODY),
				frappe.ValidationError,
			)
		# A note records who raised it; the owner is derived, never client-supplied.
		if self.is_new() or not self.note_owner:
			self.note_owner = frappe.session.user
		if self.is_new():
			self.status = "Open"
