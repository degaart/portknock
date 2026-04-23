#!/bin/bash
set -eou pipefail

CURRENT_VERSION="$(awk '$1=="version"{print $3}' Cargo.toml|tr -d '"')"
VERSION="${CURRENT_VERSION%.*}.$((${CURRENT_VERSION##*.}+1))"

sed -i "s/^version *= *.*/version = ${VERSION}/" Cargo.toml

git add -A
git commit -m "chore: v${VERSION}"
git tag -a "v${VERSION}"
echo "Version v${VERSION} tagged. Run \"git push --follow-tags\" to push"

