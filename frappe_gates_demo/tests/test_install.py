"""The install hook is part of the artifact: a site installed from this app
must come up with its seeded note, and running the hook twice must not
duplicate it (Kubernetes restarts and re-installs are not rare).
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_gates_demo import install


class TestInstall(FrappeTestCase):
	def tearDown(self):
		frappe.db.rollback()

	def test_after_install_seeds_the_welcome_note_once(self):
		frappe.db.delete("Security Note", {"title": install.SEED_TITLE})
		install.after_install()
		self.assertTrue(frappe.db.exists("Security Note", {"title": install.SEED_TITLE}))
		install.after_install()
		self.assertEqual(frappe.db.count("Security Note", {"title": install.SEED_TITLE}), 1)
