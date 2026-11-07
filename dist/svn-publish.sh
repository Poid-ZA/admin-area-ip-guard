#!/usr/bin/env bash
# Publish admin-area-ip-guard to the WordPress.org plugin SVN repository.
# Usage: svn-publish.sh <wporg-username>
# Stages trunk/ and tags/<version>/ from the release ZIP, shows svn status,
# then asks for "yes" before committing. Nothing is committed without that.
set -euo pipefail

SVN_USER="${1:?usage: svn-publish.sh <wporg-username>}"
SLUG="admin-area-ip-guard"
VERSION="1.0.0"
ZIP="$(cd "$(dirname "$0")" && pwd)/${SLUG}.zip"
SVN_URL="${SVN_URL:-https://plugins.svn.wordpress.org/${SLUG}}"

[[ -f "$ZIP" ]] || { echo "missing $ZIP"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

unzip -q "$ZIP" -d "$WORK/stage"
svn checkout "$SVN_URL" "$WORK/svn"
cd "$WORK/svn"

# Mirror the release into trunk and the version tag.
rm -rf trunk/*
cp -r "$WORK/stage/$SLUG/." trunk/
mkdir -p "tags/$VERSION"
rm -rf "tags/$VERSION/"*
cp -r trunk/. "tags/$VERSION/"

# Register new files and remove deleted ones.
svn add --force --quiet trunk "tags/$VERSION"
svn status | awk '/^!/ {print $2}' | xargs -r svn rm --force --quiet
svn status

read -r -p "Commit $SLUG $VERSION as $SVN_USER? Type yes: " ans
[[ "$ans" == "yes" ]] || { echo "not committed"; exit 1; }

svn commit -m "Release $VERSION: IP allowlist for wp-admin and wp-login.php" --username "$SVN_USER"
