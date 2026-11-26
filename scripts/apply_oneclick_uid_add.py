"""Apply the versioned Prompt 25 patch to a checkout of its base revision.

Run this script from the target repository after fetching the feature branch.
The four-file patch is stored in Git and validated before changing any files.
"""
from pathlib import Path
import subprocess

ROOT = Path.cwd()
FILES = (
    "app/models.py", "app/routers/management.py", "web/index.html",
    "tests/test_oneclick_public_uid_add.py",
)


def main():
    commit = subprocess.check_output([
        "git", "log", "--all", "-1", "--format=%H", "--diff-filter=A", "--",
        "scripts/apply_oneclick_uid_add.py",
    ], cwd=ROOT).strip().decode()
    if not commit:
        raise SystemExit("Fetch the Prompt 25 branch before applying its patch.")
    patch = subprocess.check_output(["git", "diff", commit + "^", commit, "--", *FILES], cwd=ROOT)
    for options in (["--check"], []):
        subprocess.run(["git", "apply", *options, "-"], input=patch, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
