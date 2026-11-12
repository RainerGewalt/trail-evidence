#!/usr/bin/env bash
# Prints the section of CHANGELOG.md for one version, without its heading:
# the release notes of the GitHub release (.github/workflows/release.yml).
# Fails when the section is missing or empty, so that no release goes out
# without its changelog entry.
#
# Usage: scripts/release-notes.sh 0.2.2
set -euo pipefail
version="${1:?usage: scripts/release-notes.sh <version>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
notes="$(awk -v v="$version" '
  index($0, "## " v " ") == 1 || $0 == "## " v { on = 1; next }
  on && /^## / { exit }
  on { print }
' "$root/CHANGELOG.md")"
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "release-notes: CHANGELOG.md has no section for $version" >&2
  exit 1
fi
printf '%s\n' "$notes" | sed -e '/./,$!d'
