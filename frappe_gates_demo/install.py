"""Install / migrate hooks for the demo app."""

import frappe

SEED_TITLE = "Welcome to the Frappe Gates Demo"
SEED_BODY = (
	"This note was seeded at install time. Notes are the app's only domain object — "
	"they exist so the DevSecOps gate pipeline (SAST, SCA, secrets, IaC, image scan, "
	"SBOM, signing, GitOps delivery, Kyverno admission) has a real application to "
	"build, test, scan and deploy."
)


def after_install() -> None:
	"""Seed one note so a freshly installed site is not an empty demo."""
	if frappe.db.exists("Security Note", {"title": SEED_TITLE}):
		return
	frappe.get_doc(
		{
			"doctype": "Security Note",
			"title": SEED_TITLE,
			"body": SEED_BODY,
			"severity": "Low",
			"note_owner": "Administrator",
		}
	).insert(ignore_permissions=True)
