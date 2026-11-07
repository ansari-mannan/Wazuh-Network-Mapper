#!/bin/bash
# Build the files of a GitHub Release on the development machine: one plugin zip
# per dashboard version, the ntm-<tag>.tar.gz bundle and SHA256SUMS, all in dist/.
# See docs/RELEASING.md.
#
#   scripts/build-release.sh --tag v1.0.0 [osd-version ...]     (default: 2.19.6)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
# shellcheck source=osd-version.sh source-path=SCRIPTDIR
. "$HERE/osd-version.sh"

TAG=""
VERSIONS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="${2:?--tag needs a value}"; shift 2 ;;
    -*) sed -n '6p' "$0" | sed 's/^# *//'; exit 2 ;;
    *) VERSIONS+=("$1"); shift ;;
  esac
done
[ -n "$TAG" ] || { sed -n '6p' "$0" | sed 's/^# *//'; exit 2; }
[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Not a release tag: $TAG" >&2; exit 2; }
[ "${#VERSIONS[@]}" -gt 0 ] || VERSIONS=(2.19.6)

# the bundle comes from the commit, so the zips must come from the same code
if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
  echo "The working tree has changes; commit them first." >&2
  exit 1
fi

DIST="$REPO/dist"
rm -rf "$DIST"
mkdir -p "$DIST"

for version in "${VERSIONS[@]}"; do
  build_plugin_zip "$version"
  cp "$PLUGIN_DIR/build/vulnmapper-$version.zip" "$DIST/"
done

# git archive takes only tracked files, so env files and caches cannot get in.
# wheels/ lets pip work on a server without network (ntm-install.sh --offline):
# pure-Python ones, so they fit any server with python 3.10 or later.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
git -C "$REPO" archive HEAD backend scripts/install-wazuh.sh scripts/uninstall-wazuh.sh \
  scripts/wazuh-lib.sh ':(exclude)backend/tests' | tar -x -C "$STAGE"
python3 -m pip download --quiet --only-binary=:all: --platform any --implementation py \
  --abi none --python-version 3.10 -r "$STAGE/backend/requirements.txt" -d "$STAGE/wheels"
tar -C "$STAGE" --owner=0 --group=0 -czf "$DIST/ntm-$TAG.tar.gz" backend scripts wheels

(cd "$DIST" && sha256sum "ntm-$TAG.tar.gz" vulnmapper-*.zip > SHA256SUMS)

echo "Ready to upload:"
ls -l "$DIST"
