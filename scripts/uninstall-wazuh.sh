#!/bin/bash
# Remove the plugin from the Wazuh dashboard: the plugin, the marked block in
# opensearch_dashboards.yml (backed up first) and the systemd drop-in. The data
# (/var/lib/vulnmapper) and credentials (/etc/vulnmapper) stay unless --purge.
# Touches nothing outside our block, our drop-in and our folders.
#
#   sudo scripts/uninstall-wazuh.sh [--purge] [--dry-run] [--prefix DIR]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=wazuh-lib.sh source-path=SCRIPTDIR
. "$HERE/wazuh-lib.sh"

DRY_RUN=0 ROOT="" PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --prefix) ROOT="${2:?}"; shift 2 ;;
    *) sed -n '7p' "$0" | sed 's/^# //'; exit 2 ;;
  esac
done
set_paths
need_root

# the plugin first: config keys without their plugin would stop the dashboard
remove_plugin

if [ -f "$YML" ] && grep -q "^$BEGIN_MARK" "$YML"; then
  TMP="$(mktemp)"
  trap 'rm -f "$TMP"' EXIT
  yml_without_block "$YML" > "$TMP"
  backup_yml
  write_yml "$TMP"
fi

if [ -f "$DROPIN" ]; then
  run rm -f "$DROPIN"
  [ -n "$(ls -A "$DROPIN_DIR" 2>/dev/null)" ] || run rmdir "$DROPIN_DIR"
fi
run systemctl daemon-reload
run systemctl restart "$SVC"

run rm -rf "$OPT"
if [ "$PURGE" = 1 ]; then
  run rm -rf "$DATA" "$ENVDIR"
  say "Removed vulnmapper with its data and credentials."
else
  say "Removed vulnmapper. Kept the data in $DATA and the credentials in $ENVDIR (--purge removes them)."
fi
