"""Cut a flawed release — the one command, so no step gets forgotten.

ROUTINE
    1. Edit CHANGELOG.md: add a `## [X.Y.Z]` section describing the changes.
    2. mise run release -- X.Y.Z
       Bumps pyproject version, re-locks uv.lock, runs the full quality gate,
       commits, tags vX.Y.Z, pushes main + tag, and creates the GitHub Release.
    3. Approve the `pypi` deployment in the Actions run -> publishes to PyPI.

GUARDS (each aborts the release before anything irreversible)
    - on `main` and in sync with origin; no uncommitted changes except CHANGELOG.md
    - tag vX.Y.Z must not already exist
    - CHANGELOG.md must already contain the `## [X.Y.Z]` section (forces notes)
    - the full gate (`mise run check`) must pass
    - CI re-checks tag == pyproject version before any PyPI upload, and the
      `pypi` environment requires a manual approval click

RECOVERY
    PyPI versions are immutable. If a bad version ships, YANK it on PyPI
    (Manage project -> Releases -> Yank) and cut the next patch — never reuse
    a version number.

Use --dry-run to preview (checks the guards and prints the release notes only).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def abort(msg: str) -> None:
    sys.exit(f"release aborted: {msg}")


def out(*cmd: str) -> str:
    """Run a command and return trimmed stdout (abort on failure)."""
    r = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
    if r.returncode != 0:
        abort(f"`{' '.join(cmd)}` failed:\n{r.stdout}{r.stderr}")
    return r.stdout.strip()


def step(*cmd: str) -> None:
    """Run a command, streaming its output (abort on failure)."""
    print(f"  $ {' '.join(cmd)}")
    if subprocess.run(cmd, cwd=ROOT, check=False).returncode != 0:
        abort(f"`{' '.join(cmd)}` failed")


def release_notes(changelog: str, version: str) -> str:
    lines, grab, body = changelog.splitlines(), False, []
    for line in lines:
        if line.startswith(f"## [{version}]"):
            grab = True
            continue
        if grab and line.startswith("## ["):
            break
        if grab:
            body.append(line)
    return "\n".join(body).strip() or f"Release {version}"


def main() -> None:
    ap = argparse.ArgumentParser(description="Cut a flawed release.")
    ap.add_argument("version", help="new version, e.g. 0.7.2 (no leading 'v')")
    ap.add_argument(
        "--dry-run", action="store_true", help="check guards + show notes, change nothing"
    )
    args = ap.parse_args()

    version = args.version.lstrip("v")
    if not SEMVER.match(version):
        abort(f"version must be X.Y.Z, got {args.version!r}")
    tag = f"v{version}"

    # ---- guards (read-only) ----
    if out("git", "branch", "--show-current") != "main":
        abort("not on main")
    others = [
        ln
        for ln in out("git", "status", "--porcelain").splitlines()
        if ln[3:].strip() != "CHANGELOG.md"
    ]
    if others:
        listing = "\n  ".join(others)
        abort(f"uncommitted changes other than CHANGELOG.md — commit or stash first:\n  {listing}")
    out("git", "fetch", "--quiet", "origin")
    if out("git", "rev-parse", "@") != out("git", "rev-parse", "@{u}"):
        abort("local main is not in sync with origin/main — pull/push first")
    if out("git", "tag", "--list", tag):
        abort(f"tag {tag} already exists")
    changelog = CHANGELOG.read_text()
    if f"## [{version}]" not in changelog:
        abort(f"CHANGELOG.md has no '## [{version}]' section — add release notes first")
    notes = release_notes(changelog, version)

    print(f"→ release {tag}\n--- notes ---\n{notes}\n-------------")
    if args.dry_run:
        print("DRY RUN — guards pass; would bump, lock, gate, commit, tag, push, and release.")
        return

    # ---- mutate ----
    pp = PYPROJECT.read_text()
    pp = re.sub(r'^version = "[^"]*"$', f'version = "{version}"', pp, count=1, flags=re.M)
    if f'version = "{version}"' not in pp:
        abort("could not set version in pyproject.toml")
    PYPROJECT.write_text(pp)
    print("→ re-locking uv.lock")
    step("uv", "lock")
    print("→ running the full quality gate")
    step("mise", "run", "check")
    print("→ committing, tagging, pushing")
    step("git", "add", "pyproject.toml", "uv.lock", "CHANGELOG.md")
    step("git", "commit", "-s", "-m", f"release: {tag}")
    step("git", "tag", "-a", tag, "-m", tag)
    step("git", "push", "origin", "main")
    step("git", "push", "origin", tag)
    print("→ creating the GitHub Release (triggers the publish workflow)")
    step("gh", "release", "create", tag, "--verify-tag", "--title", tag, "--notes", notes)

    print(
        f"\n✓ {tag} tagged, pushed, and released.\n"
        "  Final step: open the Actions run and APPROVE the `pypi` deployment to publish.\n"
        "  (Inspect the built artifacts there first — nothing reaches PyPI until you approve.)"
    )


if __name__ == "__main__":
    main()
