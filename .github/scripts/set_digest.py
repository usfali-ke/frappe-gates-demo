"""Set the images[].digest in a kustomization — the one automated edit
GitOps allows (devsecops-release.yml). Fails unless exactly one digest
line is replaced, so a changed file layout can't silently deploy nothing."""

import re
import sys

path, digest = sys.argv[1], sys.argv[2]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    sys.exit(f"not a digest: {digest!r}")
with open(path) as f:
    text, n = re.subn(r"(?m)^(    digest: )sha256:[0-9a-f]{64}$", rf"\g<1>{digest}", f.read())
if n != 1:
    sys.exit(f"expected exactly one images[].digest line in {path}, found {n}")
with open(path, "w") as f:
    f.write(text)
