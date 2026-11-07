#!/usr/bin/env bash
# Build the WordPress.org release ZIP. Output: dist/admin-area-ip-guard.zip
# The archive has one root folder named after the slug. Tests, specs, the
# user HOWTO and dist/ stay out of the release.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
SLUG="admin-area-ip-guard"
OUT="$SRC/dist/${SLUG}.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/$SLUG/includes"
cp "$SRC/admin-area-ip-guard.php" "$SRC/uninstall.php" "$SRC/readme.txt" "$STAGE/$SLUG/"
cp "$SRC/includes/rules.php" "$STAGE/$SLUG/includes/"

rm -f "$OUT"
(cd "$STAGE" && zip -r -q "$OUT" "$SLUG")
echo "built $OUT"
