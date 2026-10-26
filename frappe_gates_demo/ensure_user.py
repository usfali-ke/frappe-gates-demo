"""Create or re-password one test account on the site this bench serves.

The release pipeline's authenticated security suite needs two real accounts
(one that owns a note, one that must not see it). The password arrives on
stdin, is exported as ENSURE_USER_PASSWORD by the caller and read here, so it
never appears in a pod's argv or in `ps`.

    cd /home/frappe/frappe-bench
    printf '%s\\n' "$PASSWORD" | SITE_NAME=frappe-gates-demo.local \
        ./env/bin/python -m frappe_gates_demo.ensure_user alice@example.test

(`bench --site X execute <dotted.path>` cannot be used: this Frappe build
evaluates the name with eval() in a namespace where the app module is not
imported.)
"""

import os
import sys

import frappe


def main(argv: list[str]) -> int:
	if len(argv) != 2:
		print(__doc__)
		return 2
	email = argv[1]
	password = os.environ.get("ENSURE_USER_PASSWORD") or ""
	if not password:
		print("ENSURE_USER_PASSWORD is not set", file=sys.stderr)
		return 2

	site = os.environ.get("SITE_NAME") or "frappe-gates-demo.local"
	sites_path = os.environ.get("SITES_PATH") or os.path.join(os.getcwd(), "sites")

	# Frappe's logger writes to the RELATIVE path "../logs/<file>", so the
	# working directory decides where the bench's logs land. `bench` always
	# executes frappe with cwd = sites; do the same, or every logged query
	# dies on a path outside the bench.
	os.makedirs(os.path.join(sites_path, os.pardir, "logs"), exist_ok=True)
	os.makedirs(os.path.join(sites_path, site, "logs"), exist_ok=True)
	os.chdir(sites_path)

	frappe.init(site=site, sites_path=".")
	frappe.connect()

	from frappe_gates_demo.test_support import ensure_user

	name = ensure_user(email, password)
	frappe.db.commit()  # nosemgrep: frappe-manual-commit -- CLI entry point
	print(name)
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv))
