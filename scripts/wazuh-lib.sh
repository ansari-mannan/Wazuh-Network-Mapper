# Shared by install-wazuh.sh and uninstall-wazuh.sh: where things live on the
# Wazuh server, and the helpers that print instead of act under --dry-run.
# ROOT (--prefix) puts every system path under a test folder; the paths written
# into the dashboard's config stay the real ones.
# shellcheck shell=bash

SVC=wazuh-dashboard
BEGIN_MARK="# BEGIN vulnmapper"
END_MARK="# END vulnmapper"
OPT_REAL=/opt/vulnmapper
DATA_REAL=/var/lib/vulnmapper
ENV_REAL=/etc/vulnmapper/vulnmapper.env

# shellcheck disable=SC2034 # used by the scripts that source this
set_paths() {
  OSD="$ROOT/usr/share/wazuh-dashboard"
  YML="$ROOT/etc/wazuh-dashboard/opensearch_dashboards.yml"
  OPT="$ROOT$OPT_REAL"
  DATA="$ROOT$DATA_REAL"
  ENVDIR="$ROOT/etc/vulnmapper"
  ENVF="$ROOT$ENV_REAL"
  DROPIN_DIR="$ROOT/etc/systemd/system/$SVC.service.d"
  DROPIN="$DROPIN_DIR/vulnmapper.conf"
  PLUGIN_TOOL="$OSD/bin/opensearch-dashboards-plugin"
}

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

# run CMD...: runs it, or under --dry-run prints it
run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf 'would run:'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

# yml_without_block FILE: FILE's text without our marked block and the one
# blank line the install puts before it
yml_without_block() {
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    index($0, b) == 1 { blank = 0; skip = 1; next }
    skip { if (index($0, e) == 1) skip = 0; next }
    blank { print ""; blank = 0 }
    $0 == "" { blank = 1; next }
    { print }
    END { if (blank) print "" }' "$1"
}

# write_yml NEWFILE: puts NEWFILE's text into the dashboard config, keeping the
# config's owner and mode (cat, not mv); under --dry-run prints the diff
write_yml() {
  if [ "$DRY_RUN" = 1 ]; then
    say "would change $YML:"
    diff -u --label "$YML" --label "$YML (new)" "$YML" "$1" || true
  else
    cat "$1" > "$YML"
  fi
}

# backup_yml: a timestamped copy beside the config, its path in BACKUP
backup_yml() {
  BACKUP="$YML.vulnmapper-$(date +%Y%m%d-%H%M%S).bak"
  run cp -p "$YML" "$BACKUP"
}

plugin_installed() { [ -d "$OSD/plugins/vulnmapper" ]; }

remove_plugin() {
  if plugin_installed; then
    run sudo -u "$SVC" "$PLUGIN_TOOL" remove vulnmapper
  fi
}

need_root() {
  if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" != 0 ]; then
    say "Run this with sudo." >&2
    exit 1
  fi
}
