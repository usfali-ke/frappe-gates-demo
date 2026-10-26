"""Whitelisted API for the Frappe Gates Demo app.

This is the app's whole public surface: it exists so the DevSecOps gate
pipeline has something real to test, scan, deploy and probe. Every method
here is called by the unit tests, the env test suites and the canary
AnalysisTemplate, so a regression in any of them is visible as a gate
result, not as a silent 500 in a dashboard.
"""

import frappe
from frappe import _

from frappe_gates_demo import __version__

APP = "frappe_gates_demo"
DOCTYPE = "Security Note"
SEVERITIES = ("Low", "Medium", "High", "Critical")
MAX_LIST_LIMIT = 100


def _require_login() -> None:
	"""Guest access is refused by the API even where DocType permissions allow it."""
	if frappe.session.user in (None, "", "Guest"):
		frappe.throw(_("Login required"), frappe.PermissionError)


@frappe.whitelist(allow_guest=True)
def health() -> dict:
	"""Liveness/readiness payload for Kubernetes probes and the canary.

	Deliberately guest-readable and deliberately boring: the app name, the two
	versions and whether the database answers. No site paths, no configuration,
	no user data — a probe endpoint must never become an information leak.
	"""
	db_ok = False
	try:
		frappe.db.sql("select 1")
		db_ok = True
	except Exception:
		frappe.logger(__name__).warning("health: database check failed", exc_info=True)

	return {
		"status": "ok" if db_ok else "degraded",
		"app": APP,
		"app_version": __version__,
		"frappe_version": frappe.__version__,
		"db": db_ok,
	}


@frappe.whitelist()
def whoami() -> dict:
	"""The authenticated user and the roles the session carries."""
	_require_login()
	return {
		"user": frappe.session.user,
		"full_name": frappe.utils.get_fullname(frappe.session.user),
		"roles": [r for r in frappe.get_roles() if r not in ("All", "Guest")],
	}


@frappe.whitelist()
def notes_list(
	limit: int | str = 20,
	severity: str | None = None,
	status: str | None = None,
	search: str | None = None,
) -> list[dict]:
	"""Newest-first list of the notes the session may read."""
	_require_login()
	try:
		limit = max(1, min(int(limit), MAX_LIST_LIMIT))
	except (TypeError, ValueError):
		frappe.throw(_("limit must be an integer"), frappe.ValidationError)

	if severity and severity not in SEVERITIES:
		frappe.throw(_("Unknown severity {0}").format(severity), frappe.ValidationError)
	if status and status not in ("Open", "Closed"):
		frappe.throw(_("Unknown status {0}").format(status), frappe.ValidationError)

	filters: dict = {}
	if severity:
		filters["severity"] = severity
	if status:
		filters["status"] = status
	or_filters = None
	if search:
		or_filters = {"title": ("like", f"%{search}%"), "body": ("like", f"%{search}%")}

	rows = frappe.get_list(
		DOCTYPE,
		filters=filters,
		or_filters=or_filters,
		fields=["name", "title", "severity", "status", "note_owner", "pinned", "creation", "modified"],
		order_by="pinned desc, modified desc",
		limit_page_length=limit,
	)
	for row in rows:
		row["age_days"] = frappe.utils.date_diff(frappe.utils.nowdate(), row["creation"])
	return rows


@frappe.whitelist(methods=["POST"])
def note_create(title: str, body: str | None = None, severity: str = "Medium") -> dict:
	"""Create a note owned by the calling user. Validation lives on the DocType."""
	_require_login()
	doc = frappe.get_doc(
		{
			"doctype": DOCTYPE,
			"title": title,
			"body": body,
			"severity": severity,
			"note_owner": frappe.session.user,
			"status": "Open",
		}
	)
	doc.insert()
	frappe.db.commit()  # nosemgrep: frappe-manual-commit -- API call, no surrounding transaction
	return {"name": doc.name, "title": doc.title, "severity": doc.severity, "status": doc.status}


@frappe.whitelist(methods=["POST"])
def note_close(name: str) -> dict:
	"""Close a note the session may write."""
	_require_login()
	doc = frappe.get_doc(DOCTYPE, name)
	doc.check_permission("write")
	doc.status = "Closed"
	doc.save()
	frappe.db.commit()  # nosemgrep: frappe-manual-commit -- API call, no surrounding transaction
	return {"name": doc.name, "status": doc.status}


@frappe.whitelist()
def notes_stats() -> dict:
	"""Counts by severity/status for the notes this session may read.

	Built from `frappe.get_list`, not `get_all`: the counts are a permission-
	scoped view of the same rows the list returns, so one user's tally can
	never move when another user writes. (get_all ignores permissions —
	the first version of this method leaked the whole table's counts.)
	"""
	_require_login()
	rows = frappe.get_list(
		DOCTYPE,
		fields=["severity", "status"],
		limit_page_length=0,
	)
	by_severity = {s: 0 for s in SEVERITIES}
	open_by_severity = {s: 0 for s in SEVERITIES}
	by_status = {"Open": 0, "Closed": 0}
	for row in rows:
		if row["severity"] in by_severity:
			by_severity[row["severity"]] += 1
			if row["status"] == "Open":
				open_by_severity[row["severity"]] += 1
		if row["status"] in by_status:
			by_status[row["status"]] += 1
	return {
		"total": sum(by_severity.values()),
		"by_severity": by_severity,
		"by_status": by_status,
		"open": by_status["Open"],
		"highest_open_severity": next(
			(s for s in reversed((*SEVERITIES,)) if open_by_severity[s]),
			None,
		),
	}
