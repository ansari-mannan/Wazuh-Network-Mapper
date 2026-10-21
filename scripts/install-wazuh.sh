#!/bin/bash
# Install (or upgrade in place) the plugin into the Wazuh dashboard on this
# server: the scanner in /opt/vulnmapper, its data in /var/lib/vulnmapper, its
# credentials in /etc/vulnmapper/vulnmapper.env (passed to the dashboard by a
# systemd drop-in), a marked block in opensearch_dashboards.yml, then the
# plugin itself. If the dashboard does not come back, everything is undone.
#
#   sudo scripts/install-wazuh.sh [options] vulnmapper-2.19.6.zip
#     --env-from FILE    copy this env file (e.g. ~/.vulnmapper.env) to /etc/vulnmapper
#     --import-data DIR  copy an existing data folder (graph.json, history, ...) in;
#                        files already in /var/lib/vulnmapper are kept
#     --section NAME     the Wazuh Overview section for the card
#                        (default: the installed one, else "THREAT INTELLIGENCE")
#     --dry-run          print what would be done, change nothing
#     --prefix DIR       treat DIR as / (for tests)
set -u
umask 022
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
# shellcheck source=wazuh-lib.sh source-path=SCRIPTDIR
. "$HERE/wazuh-lib.sh"

DRY_RUN=0 ROOT="" ENV_FROM="" IMPORT_DATA="" SECTION="" ZIP=""
usage() { sed -n '8,16p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --env-from) ENV_FROM="${2:?}"; shift 2 ;;
    --import-data) IMPORT_DATA="${2:?}"; shift 2 ;;
    --section) SECTION="${2:?}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --prefix) ROOT="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    -*) say "Unknown option $1" >&2; usage ;;
    *) ZIP="$1"; shift ;;
  esac
done
[ -n "$ZIP" ] || usage
set_paths
need_root

die() { say "error: $*" >&2; exit 1; }

# --- a) preflight: nothing is changed until all of this passes ---------------
[ -f "$ZIP" ] || die "no zip at $ZIP"
ZIP="$(cd "$(dirname "$ZIP")" && pwd)/$(basename "$ZIP")"
command -v python3 >/dev/null || die "python3 is not installed"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
  || die "python3 is $(python3 -V 2>&1 | cut -d' ' -f2); 3.10 or later is needed"
python3 -c 'import venv, ensurepip' 2>/dev/null \
  || die "python3 cannot make a venv; install the python3-venv package"
command -v nmap >/dev/null || warn "nmap is not installed; the optional service scan of unmanaged hosts will not work"

DASH_VERSION="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$OSD/package.json" 2>/dev/null)" \
  || die "no Wazuh dashboard found ($OSD/package.json)"
ZIP_VERSION="$(python3 - "$ZIP" <<'EOF'
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    name = next(n for n in z.namelist() if n.endswith("/vulnmapper/opensearch_dashboards.json"))
    print(json.loads(z.read(name))["opensearchDashboardsVersion"])
EOF
)" || die "$ZIP is not a vulnmapper plugin zip"
[ "$ZIP_VERSION" = "$DASH_VERSION" ] \
  || die "the zip is built for dashboard $ZIP_VERSION but this one is $DASH_VERSION; build it with OSD_VERSION=$DASH_VERSION ./scripts/send-plugin.sh"

# under --dry-run (e.g. against a test prefix) these only warn
dry_or_die() { if [ "$DRY_RUN" = 1 ]; then warn "$*"; else die "$*"; fi; }
systemctl is-active --quiet "$SVC" 2>/dev/null || dry_or_die "$SVC is not active; start it first (systemctl status $SVC)"
id "$SVC" >/dev/null 2>&1 || dry_or_die "no $SVC user"
[ -f "$YML" ] || die "no dashboard config at $YML"
[ -z "$ENV_FROM" ] || [ -f "$ENV_FROM" ] || die "no env file at $ENV_FROM"
[ -z "$IMPORT_DATA" ] || [ -d "$IMPORT_DATA" ] || die "no data folder at $IMPORT_DATA"
# a vulnmapper.* setting outside our block would be a duplicate key, which stops the dashboard
if yml_without_block "$YML" | grep -q '^[[:space:]]*vulnmapper[.:]'; then
  die "$YML already has vulnmapper settings outside the '$BEGIN_MARK' block; move or remove them first"
fi
# keep the section chosen at the last install unless a new one is given
[ -n "$SECTION" ] || SECTION="$(sed -n "/^$BEGIN_MARK/,/^$END_MARK/s/^vulnmapper\.wazuhCard\.section: *\"\(.*\)\"$/\1/p" "$YML")"
SECTION="${SECTION:-THREAT INTELLIGENCE}"
[[ "$SECTION" =~ ^[A-Za-z][A-Za-z0-9\ \&-]*$ ]] || die "--section takes letters, digits, spaces, & and - only"

# --- b) files -----------------------------------------------------------------
say "Copying the scanner to $OPT/backend"
run mkdir -p "$OPT"
run rm -rf "$OPT/backend"
# local env files may hold credentials; only the code and the example go
run tar -C "$REPO" --exclude=.env --exclude='*.env' --exclude=__pycache__ --exclude=.pytest_cache \
  --no-same-owner -cf "$OPT/backend.tar" backend
run tar -C "$OPT" --no-same-owner -xf "$OPT/backend.tar"
run rm -f "$OPT/backend.tar"
[ -x "$OPT/venv/bin/python" ] || run python3 -m venv "$OPT/venv"
say "Installing the scanner's Python packages"
run "$OPT/venv/bin/python" -m pip install --quiet --retries 5 --timeout 60 -r "$OPT/backend/requirements.txt" \
  || die "pip could not install backend/requirements.txt (nothing in the dashboard was changed yet)"
# the service user cannot write beside the code; compile now so it never tries
run "$OPT/venv/bin/python" -m compileall -q "$OPT/backend/vulnmapper"
# python -m vulnmapper... from any folder (the feeds refresh command below)
run sh -c 'echo "$2" > "$("$1" -c "import sysconfig; print(sysconfig.get_path(\"purelib\"))")/vulnmapper.pth"' \
  sh "$OPT/venv/bin/python" "$OPT_REAL/backend"

run install -d -o "$SVC" -g "$SVC" -m 750 "$DATA"
if [ -n "$IMPORT_DATA" ]; then
  say "Importing $IMPORT_DATA into $DATA (files already there are kept)"
  run cp -a --no-clobber "$IMPORT_DATA/." "$DATA/"
  run chown -R "$SVC:$SVC" "$DATA"
fi

run install -d -o root -g "$SVC" -m 750 "$ENVDIR"
NEW_ENV=0
if [ -n "$ENV_FROM" ]; then
  say "Copying $ENV_FROM to $ENVF"
  # systemd's EnvironmentFile has no 'export'
  run sh -c 'sed "s/^[[:space:]]*export[[:space:]]\{1,\}//" "$1" > "$2"' sh "$ENV_FROM" "$ENVF"
elif [ ! -f "$ENVF" ]; then
  NEW_ENV=1
  run cp "$REPO/backend/.env.example" "$ENVF"
fi
run chown "root:$SVC" "$ENVF"
run chmod 640 "$ENVF"

# --- c) config ----------------------------------------------------------------
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
{
  yml_without_block "$YML"
  printf '\n%s (managed by scripts/install-wazuh.sh; nothing secret here)\n' "$BEGIN_MARK"
  printf 'vulnmapper.backendDir: %s/backend\n' "$OPT_REAL"
  printf 'vulnmapper.pythonBin: %s/venv/bin/python\n' "$OPT_REAL"
  printf 'vulnmapper.graphPath: %s/graph.json\n' "$DATA_REAL"
  printf 'vulnmapper.liveness.enabled: true\n'
  printf 'vulnmapper.liveness.autoRescan: false\n'
  printf 'vulnmapper.wazuhCard.section: "%s"\n' "$SECTION"
  printf '%s\n' "$END_MARK"
} > "$TMP"

rollback() {
  say "The dashboard did not come back; undoing the install." >&2
  sudo -u "$SVC" "$PLUGIN_TOOL" remove vulnmapper >/dev/null 2>&1
  # the backup may hold an older block, which without the plugin would stop the dashboard too
  if [ -n "${BACKUP:-}" ] && [ -f "$BACKUP" ]; then
    yml_without_block "$BACKUP" > "$TMP" && cat "$TMP" > "$YML"
  fi
  rm -f "$DROPIN"
  systemctl daemon-reload
  systemctl restart "$SVC"
  say "Last 50 lines of the $SVC journal:" >&2
  journalctl -u "$SVC" -n 50 --no-pager >&2
  exit 1
}

backup_yml
write_yml "$TMP"

# --- d) secrets: the env file reaches the dashboard (and so the scanner) --------
run mkdir -p "$DROPIN_DIR"
if [ "$DRY_RUN" = 1 ]; then
  say "would write $DROPIN: EnvironmentFile=$ENV_REAL"
else
  printf '[Service]\nEnvironmentFile=%s\n' "$ENV_REAL" > "$DROPIN"
fi
run systemctl daemon-reload || rollback

# --- e) the plugin ------------------------------------------------------------
# the plugin tool runs as the service user, which may not read the caller's home
run install -m 644 "$ZIP" "$OPT/vulnmapper-$ZIP_VERSION.zip"
remove_plugin || rollback
run sudo -u "$SVC" "$PLUGIN_TOOL" install "file://$OPT_REAL/vulnmapper-$ZIP_VERSION.zip" || rollback

# --- f) restart and check -----------------------------------------------------
say "Restarting $SVC (the first start after an install can take a few minutes)"
run systemctl restart "$SVC" || rollback
code() { curl -sk -o /dev/null -m 10 -w '%{http_code}' "https://127.0.0.1:443$1"; }
if [ "$DRY_RUN" = 1 ]; then
  say "would wait up to 5 minutes for https://127.0.0.1:443/api/status (200 or 401), then check /app/vulnmapper"
else
  up=0
  for _ in $(seq 1 60); do
    case "$(code /api/status)" in 200|401) up=1; break ;; esac
    sleep 5
  done
  [ "$up" = 1 ] || rollback
  # 200, or a redirect to the login page when the security plugin wants a sign-in
  case "$(code /app/vulnmapper)" in 200|302) ;; *) rollback ;; esac
  systemctl is-active --quiet "$SVC" || rollback
fi

# --- g) summary -----------------------------------------------------------------
cat <<EOF

Installed vulnmapper for dashboard $DASH_VERSION.
  scanner      $OPT_REAL/backend (Python in $OPT_REAL/venv)
  data         $DATA_REAL (graph.json, caches, history)
  credentials  $ENV_REAL (root:$SVC, 640), given to $SVC by
               /etc/systemd/system/$SVC.service.d/vulnmapper.conf
  settings     the "$BEGIN_MARK" block in /etc/wazuh-dashboard/opensearch_dashboards.yml
               (backup: ${BACKUP#"$ROOT"})
EOF
if [ "$NEW_ENV" = 1 ]; then
  cat <<EOF

The credentials file is new: fill it in (Wazuh API, Indexer, SNMP), then
restart the dashboard:
  sudoedit $ENV_REAL
  sudo systemctl restart $SVC
EOF
fi
cat <<EOF

Open it from the "Network Topology Mapper" card in the $SECTION section of
Wazuh's Overview page, from the menu (Security), or at https://<server>/app/vulnmapper.
To move the card: sudo $0 --section "ENDPOINT SECURITY" <zip>
(or edit vulnmapper.wazuhCard.section in the block and restart $SVC).
Refresh the threat feeds by hand with:
  sudo -u $SVC $OPT_REAL/venv/bin/python -m vulnmapper.scoring.feeds --refresh --cache-dir $DATA_REAL
EOF
