"""Test-environment helpers that have to run inside the deployed pod.

The release pipeline's environment suites need two real accounts with real
passwords (the security suite proves one account cannot read the other's
notes). Creating them from the pipeline keeps the credentials on the
runner's disk and out of git: the password arrives on stdin, is exported as
ENSURE_USER_PASSWORD and read HERE, so it never appears in the pod's argv.

    ENSURE_USER_PASSWORD=... bench --site <site> execute \\
        frappe_gates_demo.test_support.ensure_user_from_env --kwargs '{"email": "a@example.test"}'
"""

import os

import frappe

DEFAULT_ROLES = ("All", "Desk User")


def ensure_user(email: str, password: str, roles=DEFAULT_ROLES) -> str:
	"""Create (or re-enable and re-password) one test account."""
	if not password:
		raise ValueError("a password is required")
	if frappe.db.exists("User", email):
		user = frappe.get_doc("User", email)
		user.enabled = 1
	else:
		user = frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": email.split("@")[0][:40],
				"send_welcome_email": 0,
				"roles": [{"role": role} for role in roles],
			}
		)
		user.insert(ignore_permissions=True)
	user.new_password = password
	user.save(ignore_permissions=True)
	return user.name


def ensure_user_from_env(email: str) -> str:
	"""bench-execute entry point: the password comes from the environment."""
	password = os.environ.get("ENSURE_USER_PASSWORD") or ""
	if not password:
		raise ValueError("ENSURE_USER_PASSWORD is not set")
	name = ensure_user(email, password)
	frappe.db.commit()  # nosemgrep: frappe-manual-commit -- CLI entry point
	return name
