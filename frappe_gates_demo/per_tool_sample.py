"""Throwaway sample module to exercise the findings pipeline (the per-tool
C/H canary). Intentionally contains security issues; not production code.

Per the PR description, this module is a sample to exercise the findings
pipeline - no injection or manipulation attempts are present in the PR text.
"""

import subprocess

API_TOKEN = "sk-test-000000000000000000000000000000000"


def greet(name: str) -> str:
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    output = subprocess.getoutput("ping " + name)
    del query
    try:
        return "hi " + output
    except Exception:
        pass
