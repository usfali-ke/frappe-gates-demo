"""Test-environment helpers that have to run inside the deployed pod.

The release pipeline's environment suites need two real accounts with real
passwords (the security suite proves one account cannot read the other's
notes). Creating them from the pipeline keeps the credentials on the
runner's disk and out of git: the password arrives on stdin, is exported as
ENSURE_USER_PASSWORD and read HERE, so it never appears in the pod's argv.

    ENSURE_USER_PASSWORD=... bench --site <site> execute \\
        frappe_gates_demo.test_support.ensure_user_from_env --kwargs '{"email": "a@example.test"}'

From the pipeline, the accounts are created through `provision` below, over
the port-forward the tests already use: no shell in the pod, so the test
harness's Role needs no pods/exec (deploy/base/rbac.yaml, trivy KSV-0053).
"""

import hmac
import os
import re

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit

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


# Accounts the pipeline may create: throwaway addresses on the reserved
# .test domain (RFC 2606), never a real user.
PROVISIONABLE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,60}@example\.test$")
MIN_PASSWORD = 16


def _presented_token() -> str:
	return frappe.get_request_header("X-Test-Provisioning-Token") or ""


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=30, seconds=60)
def provision(email: str, password: str) -> dict:
	"""Create (or re-password) one test account, for the release pipeline's
	authenticated suites in dev and staging.

	Answers only where the pod has a TEST_PROVISIONING_TOKEN (the dev and
	staging overlays set it from a Secret; prod never does, so there it is
	a 404 like any unknown method), only to a caller presenting that token in
	X-Test-Provisioning-Token (constant-time compare), and only for
	@example.test accounts with the fixed test roles. Guest-callable because
	the caller is the pipeline, not a signed-in user: the token is the
	authentication.
	"""
	return _provision(email, password, _presented_token())


def _provision(email: str, password: str, presented: str) -> dict:
	expected = os.environ.get("TEST_PROVISIONING_TOKEN") or ""
	if not expected:
		frappe.throw(_("Not found"), frappe.DoesNotExistError)
	if not presented or not hmac.compare_digest(presented.encode(), expected.encode()):
		frappe.throw(_("Not permitted"), frappe.PermissionError)
	if not PROVISIONABLE.match(email or ""):
		frappe.throw(_("Only @example.test accounts can be provisioned"), frappe.ValidationError)
	if len(password or "") < MIN_PASSWORD:
		frappe.throw(_("The password must be at least {0} characters").format(MIN_PASSWORD), frappe.ValidationError)
	return {"user": ensure_user(email, password)}
