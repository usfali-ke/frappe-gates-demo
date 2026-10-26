"""A tiny server-rendered notes page — the app's human surface.

The demo exists to give the gate pipeline something real to build, test,
deploy and watch, so it needs one page a person can actually open: the note
list, the form that creates a note, and the counts the API also returns.
Desk (the /app UI) is Frappe's admin console, not this app's product surface.
"""

import frappe
from frappe import _

from frappe_gates_demo import api

no_cache = 1


def get_context(context):
	if frappe.session.user == "Guest":
		frappe.local.flags.redirect_location = "/login?redirect-to=/notes"
		raise frappe.Redirect

	context.no_cache = 1
	context.title = _("Security notes")
	context.user = frappe.session.user
	context.full_name = frappe.utils.get_fullname(frappe.session.user)
	context.notes = api.notes_list(limit=50)
	context.stats = api.notes_stats()
	context.severities = api.SEVERITIES
	return context
