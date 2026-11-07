#!/bin/bash
# One-command install of the Network Topology Mapper on a running Wazuh server.
# This is the only file the user has, so it sources nothing: it fetches a
# release, checks it against SHA256SUMS and hands over to the release's own
# install-wazuh.sh or uninstall-wazuh.sh.
#
#   curl -sO https://raw.githubusercontent.com/ansari-mannan/Wazuh-Network-Mapper/main/scripts/ntm-install.sh
#   sudo bash ntm-install.sh -i
set -Eeuo pipefail

REPO_SLUG=ansari-mannan/Wazuh-Network-Mapper
ENV_PATH=/etc/vulnmapper/vulnmapper.env
WAZUH_YML=/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
MAIN_LOG=/var/log/ntm-install.log

ACTION="" TAG="" OFFLINE="" ENV_FROM="" IMPORT_DATA="" SECTION="" ROOT=""
DRY_RUN=0 PURGE=0 YES=0 VERBOSE=0 VERIFY_TLS=0 CRED_FLAGS=0
WAZUH_HOST="" WAZUH_PORT="" WAZUH_USER="" WAZUH_PASS=""
INDEXER_HOST="" INDEXER_PORT="" INDEXER_USER="" INDEXER_PASS="" SNMP_COMMUNITY=""
LOG=/dev/null STEP="reading the options" WORK="" SRC="" BUNDLE="" ZIP="" OSD_VERSION=""
ASSETS=() PASS_ON=()

usage() {
  cat <<'EOF'
Usage: sudo bash ntm-install.sh -i|-u [options]

  -i, --install           install, or upgrade what is installed
  -u, --uninstall         remove it; data and credentials stay unless --purge
      --purge             with -u: also remove the data and credentials
      --version TAG       this release (default: the latest)
      --offline DIR       take the bundle, zip and SHA256SUMS from DIR, no network
      --env-from FILE     use this env file instead of asking for credentials
      --import-data DIR   copy an existing data folder in
      --section NAME      the Wazuh Overview section for the card
      --dry-run           print what would be done, change nothing
      --prefix DIR        treat DIR as / (for tests)
  -y                      no prompts; stop if a required value is missing
  -v                      show package manager output as well
  -h, --help              this text

Credentials, used when there is no env file yet or its WAZUH_PASS or INDEXER_PASS
is empty (an env file with both is kept untouched):
      --wazuh-host H --wazuh-port P --wazuh-user U --wazuh-pass S
      --indexer-host H --indexer-port P --indexer-user U --indexer-pass S
      --snmp-community S  optional
      --verify-tls        verify TLS certificates (default: off)

Passwords given as flags show up in the process list; leave them out to be
asked instead.
EOF
}

log() { printf '%s %s: %s\n' "$(date '+%d/%m/%Y %H:%M:%S')" "$1" "$2" | tee -a "$LOG"; }
step() { STEP="$1"; log INFO "$1"; }

fail() {
  trap - ERR
  local hint=""
  [ "$LOG" = /dev/null ] || hint=" See $LOG."
  log ERROR "Stopped at: $STEP (exit $1).$hint" >&2
  exit "$1"
}
die() { log ERROR "$*" >&2; fail 1; }

# logged CMD...: the output goes to the log, and to the terminal with -v
logged() {
  if [ "$VERBOSE" = 1 ]; then "$@" 2>&1 | tee -a "$LOG"; else "$@" >> "$LOG" 2>&1; fi
}

need_value() { [ $# -ge 2 ] || die "$1 needs a value"; }

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -i|--install) [ "$ACTION" != uninstall ] || die "-i and -u exclude each other"; ACTION=install; shift ;;
      -u|--uninstall) [ "$ACTION" != install ] || die "-i and -u exclude each other"; ACTION=uninstall; shift ;;
      --purge) PURGE=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --verify-tls) VERIFY_TLS=1; CRED_FLAGS=1; shift ;;
      -y) YES=1; shift ;;
      -v) VERBOSE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --version) need_value "$@"; TAG="$2"; shift 2 ;;
      --offline) need_value "$@"; OFFLINE="$2"; shift 2 ;;
      --env-from) need_value "$@"; ENV_FROM="$2"; shift 2 ;;
      --import-data) need_value "$@"; IMPORT_DATA="$2"; shift 2 ;;
      --section) need_value "$@"; SECTION="$2"; shift 2 ;;
      --prefix) need_value "$@"; ROOT="$2"; shift 2 ;;
      --wazuh-host) need_value "$@"; WAZUH_HOST="$2"; CRED_FLAGS=1; shift 2 ;;
      --wazuh-port) need_value "$@"; WAZUH_PORT="$2"; CRED_FLAGS=1; shift 2 ;;
      --wazuh-user) need_value "$@"; WAZUH_USER="$2"; CRED_FLAGS=1; shift 2 ;;
      --wazuh-pass) need_value "$@"; WAZUH_PASS="$2"; CRED_FLAGS=1; shift 2 ;;
      --indexer-host) need_value "$@"; INDEXER_HOST="$2"; CRED_FLAGS=1; shift 2 ;;
      --indexer-port) need_value "$@"; INDEXER_PORT="$2"; CRED_FLAGS=1; shift 2 ;;
      --indexer-user) need_value "$@"; INDEXER_USER="$2"; CRED_FLAGS=1; shift 2 ;;
      --indexer-pass) need_value "$@"; INDEXER_PASS="$2"; CRED_FLAGS=1; shift 2 ;;
      --snmp-community) need_value "$@"; SNMP_COMMUNITY="$2"; CRED_FLAGS=1; shift 2 ;;
      *) usage >&2; die "Unknown option $1" ;;
    esac
  done
  [ -n "$ACTION" ] || { usage >&2; die "Say -i to install or -u to uninstall"; }
  [ "$PURGE" = 0 ] || [ "$ACTION" = uninstall ] || die "--purge goes with -u"
  [ -z "$TAG" ] || [[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || die "Not a release tag: $TAG"
}

check_system() {
  step "Checking this system"
  if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" != 0 ]; then
    die "Run this with sudo."
  fi
  local tool
  for tool in curl tar sha256sum python3; do
    command -v "$tool" >/dev/null || die "$tool is not installed"
  done
  # a dry run by a normal user cannot write there, and that is no reason to stop
  if { touch "$MAIN_LOG" && chmod 600 "$MAIN_LOG"; } 2>/dev/null; then
    LOG="$MAIN_LOG"
  elif [ "$DRY_RUN" != 1 ]; then
    die "cannot write $MAIN_LOG"
  fi
}

pkg_install() {
  if command -v apt-get >/dev/null; then
    logged env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" && return
    logged apt-get update
    logged env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif command -v dnf >/dev/null; then
    logged dnf install -y "$@"
  elif command -v yum >/dev/null; then
    logged yum install -y "$@"
  else
    return 1
  fi
}

install_packages() {
  step "Checking required packages"
  local venv_ok=1 nmap_ok=1 venv_pkg=python3-venv
  python3 -c 'import venv, ensurepip' 2>/dev/null || venv_ok=0
  command -v nmap >/dev/null || nmap_ok=0
  # dnf's python3 has venv built in; what it can lack is the pip that ensurepip needs
  command -v apt-get >/dev/null || venv_pkg=python3-pip

  if [ "$venv_ok" = 1 ] && [ "$nmap_ok" = 1 ]; then
    return
  fi
  if [ "$DRY_RUN" = 1 ] || [ -n "$OFFLINE" ]; then
    local why="--dry-run"
    [ "$DRY_RUN" = 1 ] || why="--offline"
    [ "$venv_ok" = 1 ] || log WARN "$venv_pkg is missing and $why installs no packages; without it the install stops at its checks"
    [ "$nmap_ok" = 1 ] || log WARN "nmap is missing and $why installs no packages; the optional service scan of unmanaged hosts will not work"
    return
  fi
  if [ "$venv_ok" = 0 ]; then
    log INFO "Installing $venv_pkg"
    pkg_install "$venv_pkg" || die "could not install $venv_pkg; install it by hand and run this again"
  fi
  if [ "$nmap_ok" = 0 ]; then
    log INFO "Installing nmap"
    pkg_install nmap || log WARN "could not install nmap; the optional service scan of unmanaged hosts will not work"
  fi
}

read_osd_version() {
  step "Reading the dashboard version"
  local file="$ROOT/usr/share/wazuh-dashboard/package.json"
  [ -f "$file" ] || die "No Wazuh dashboard on this server ($file not found). Install Wazuh first."
  OSD_VERSION="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$file" 2>/dev/null)" \
    || die "cannot read the version from $file"
  [[ "$OSD_VERSION" =~ ^[0-9]+(\.[0-9]+)+$ ]] || die "odd dashboard version in $file: $OSD_VERSION"
  log INFO "Wazuh dashboard is OpenSearch Dashboards $OSD_VERSION"
}

has_asset() {
  local name
  for name in "${ASSETS[@]}"; do
    [ "$name" != "$1" ] || return 0
  done
  return 1
}

# fills ASSETS and TAG from the GitHub API
list_online_assets() {
  local url="https://api.github.com/repos/$REPO_SLUG/releases/latest" code
  [ -z "$TAG" ] || url="https://api.github.com/repos/$REPO_SLUG/releases/tags/$TAG"
  code="$(curl -sL -m 30 -H 'Accept: application/vnd.github+json' -o "$WORK/release.json" -w '%{http_code}' "$url")" \
    || die "cannot reach api.github.com; on a server without internet use --offline"
  case "$code" in
    200) ;;
    404) die "No release ${TAG:-published yet} at github.com/$REPO_SLUG" ;;
    403|429) die "GitHub refused the request (rate limit?); try later or use --version with --offline" ;;
    *) die "GitHub answered HTTP $code for $url" ;;
  esac
  mapfile -t ASSETS < <(python3 -c '
import json, sys
release = json.load(open(sys.argv[1]))
print(release["tag_name"])
for asset in release.get("assets", []):
    print(asset["name"])' "$WORK/release.json")
  [ "${#ASSETS[@]}" -gt 0 ] || die "could not read GitHub's answer"
  TAG="${ASSETS[0]}"
  [[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || die "GitHub gave an odd tag: $TAG"
}

# fills ASSETS from the folder, and TAG when the folder holds only one bundle
list_offline_assets() {
  [ -d "$OFFLINE" ] || die "no folder at $OFFLINE"
  local file name bundles=()
  for file in "$OFFLINE"/*; do
    [ -f "$file" ] || continue
    name="${file##*/}"
    ASSETS+=("$name")
    if [[ "$name" == ntm-*.tar.gz ]]; then
      bundles+=("$name")
    fi
  done
  if [ -z "$TAG" ]; then
    [ "${#bundles[@]}" -gt 0 ] || die "no ntm-<tag>.tar.gz in $OFFLINE"
    [ "${#bundles[@]}" = 1 ] || die "$OFFLINE holds several bundles (${bundles[*]}); pick one with --version"
    name="${bundles[0]#ntm-}"
    TAG="${name%.tar.gz}"
  fi
}

resolve_release() {
  step "Finding the release"
  if [ -n "$OFFLINE" ]; then list_offline_assets; else list_online_assets; fi
  BUNDLE="ntm-$TAG.tar.gz"
  has_asset "$BUNDLE" || die "release $TAG has no $BUNDLE"
  has_asset SHA256SUMS || die "release $TAG has no SHA256SUMS"
  log INFO "Using release $TAG"

  [ "$ACTION" = install ] || return 0
  ZIP="vulnmapper-$OSD_VERSION.zip"
  if ! has_asset "$ZIP"; then
    local name have=""
    for name in "${ASSETS[@]}"; do
      if [[ "$name" == vulnmapper-*.zip ]]; then
        name="${name#vulnmapper-}"
        have="$have ${name%.zip}"
      fi
    done
    die "Release $TAG has no plugin for dashboard $OSD_VERSION. It has:${have:- none}"
  fi
}

# an entry missing from SHA256SUMS is a failure too, which sha256sum -c --ignore-missing would pass
verify() {
  local want got
  want="$(awk -v n="$1" '$2 == n || $2 == "*" n { print $1; exit }' "$SRC/SHA256SUMS")"
  [ -n "$want" ] || die "$1 is not listed in SHA256SUMS"
  got="$(sha256sum "$SRC/$1" | cut -d' ' -f1)"
  [ "$got" = "$want" ] || die "Checksum mismatch for $1: the file is damaged or was changed. Nothing was installed."
}

fetch_release() {
  step "Fetching and checking the files"
  local names=("$BUNDLE") name
  [ -z "$ZIP" ] || names+=("$ZIP")
  if [ -n "$OFFLINE" ]; then
    SRC="$OFFLINE"
  else
    SRC="$WORK/download"
    mkdir -p "$SRC"
    for name in SHA256SUMS "${names[@]}"; do
      curl -fsSL --retry 3 -o "$SRC/$name" "https://github.com/$REPO_SLUG/releases/download/$TAG/$name" \
        || die "could not download $name"
    done
  fi
  for name in "${names[@]}"; do
    verify "$name"
  done
  mkdir -p "$WORK/bundle"
  tar -xzf "$SRC/$BUNDLE" -C "$WORK/bundle" --no-same-owner
  [ -f "$WORK/bundle/scripts/install-wazuh.sh" ] && [ -f "$WORK/bundle/backend/.env.example" ] \
    || die "$BUNDLE does not look like an NTM bundle"
}

# ask VAR LABEL: shows the current value; Enter keeps it
ask() {
  local reply
  IFS= read -r -p "$2 [${!1}]: " reply || die "no terminal to ask on; use -y with the --wazuh-* and --indexer-* flags"
  [ -z "$reply" ] || printf -v "$1" '%s' "$reply"
}

# ask_secret VAR LABEL: hidden; Enter keeps the current value
ask_secret() {
  local reply
  IFS= read -rs -p "$2: " reply || die "no terminal to ask on; use -y with the --wazuh-* and --indexer-* flags"
  printf '\n' >&2
  [ -z "$reply" ] || printf -v "$1" '%s' "$reply"
}

# prints the first username and password of wazuh.yml, one per line. The system
# python may have no yaml module, and this file only holds simple scalars.
read_wazuh_yml() {
  python3 - "$1" <<'EOF'
import re, sys
found = {}
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = re.match(r"\s*(?:-\s+)?(username|password)\s*:\s*(.*?)\s*$", line)
    if not m or m[1] in found:
        continue
    value = m[2]
    double = re.match(r'"((?:[^"\\]|\\.)*)"', value)
    single = re.match(r"'((?:[^']|'')*)'", value)
    if double:
        value = re.sub(r"\\(.)", r"\1", double[1])
    elif single:
        value = single[1].replace("''", "'")
    else:
        value = re.sub(r"\s+#.*$", "", value)
    found[m[1]] = value
if "username" in found and "password" in found:
    print(found["username"])
    print(found["password"])
EOF
}

# try_login LABEL METHOD URL USER PASSWORD. The login goes through curl's stdin
# so the password stays out of the process list.
try_login() {
  local login="$4:$5" code opts=(-s -o /dev/null -m 10 -w '%{http_code}' -X "$2" -K -)
  login="${login//\\/\\\\}"
  login="${login//\"/\\\"}"
  [ "$VERIFY_TLS" = 1 ] || opts+=(-k)
  code="$(printf 'user = "%s"\n' "$login" | curl "${opts[@]}" "$3")" || true
  case "$code" in
    200) log INFO "$1 login works"; return 0 ;;
    401|403) log WARN "$1 refused the user or password ($3)" ;;
    000|"") log WARN "No answer from $1 at $3 (host, port, or its certificate with --verify-tls)" ;;
    *) log WARN "$1 answered HTTP $code at $3" ;;
  esac
  return 1
}

good_host_port() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] && [[ "$2" =~ ^[0-9]+$ ]] && return 0
  log WARN "Not a host and port: $1 $2"
  return 1
}

try_wazuh() {
  good_host_port "$WAZUH_HOST" "$WAZUH_PORT" \
    && try_login "the Wazuh API" POST "https://$WAZUH_HOST:$WAZUH_PORT/security/user/authenticate" "$WAZUH_USER" "$WAZUH_PASS"
}

try_indexer() {
  good_host_port "$INDEXER_HOST" "$INDEXER_PORT" \
    && try_login "the Wazuh indexer" GET "https://$INDEXER_HOST:$INDEXER_PORT/" "$INDEXER_USER" "$INDEXER_PASS"
}

# prints KEY=value for each assignment in an env file, read the way systemd reads
# it. Parsed, not sourced: the file is data, and this runs as root.
parse_env_file() {
  python3 - "$1" <<'EOF'
import re, sys
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
    if not m:
        continue
    value = m[2]
    double = re.fullmatch(r'"((?:[^"\\]|\\.)*)"', value)
    single = re.fullmatch(r"'([^']*)'", value)
    if double:
        value = re.sub(r'\\(["\\`$])', r"\1", double[1])
    elif single:
        value = single[1]
    else:
        value = re.sub(r"\\(.)", r"\1", value)
    print(f"{m[1]}={value}")
EOF
}

# load_env FILE ARRAY: the assignments of FILE into the associative ARRAY
load_env() {
  local -n into="$2"
  local line
  while IFS= read -r line; do
    # shellcheck disable=SC2034 # into is a nameref to the caller's array
    into["${line%%=*}"]="${line#*=}"
  done < <(parse_env_file "$1")
}

# systemd's EnvironmentFile reads a double-quoted value back exactly when these
# four are escaped; a password may hold any of them
env_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\`/\\\`}"
  value="${value//\$/\\\$}"
  printf '"%s"' "$value"
}

# write_env TEMPLATE: TEMPLATE with our values, so its variable names, comments
# and every other setting stay; a value it has no line for goes at the end
write_env() {
  local -A values=(
    [WAZUH_HOST]="$WAZUH_HOST" [WAZUH_PORT]="$WAZUH_PORT"
    [WAZUH_USER]="$WAZUH_USER" [WAZUH_PASS]="$WAZUH_PASS"
    [INDEXER_HOST]="$INDEXER_HOST" [INDEXER_PORT]="$INDEXER_PORT"
    [INDEXER_USER]="$INDEXER_USER" [INDEXER_PASS]="$INDEXER_PASS"
    [VULNMAPPER_SNMP_COMMUNITY]="$SNMP_COMMUNITY"
  )
  [ "$VERIFY_TLS" = 0 ] || values[VULNMAPPER_VERIFY_TLS]=true
  local -A seen=()
  local line key
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Z0-9_]+)[[:space:]]*= ]] \
      && [ -n "${values[${BASH_REMATCH[2]}]:-}" ]; then
      key="${BASH_REMATCH[2]}"
      seen[$key]=1
      env_line "$key" "${values[$key]}"
    else
      printf '%s\n' "$line"
    fi
  done < "$1"
  for key in "${!values[@]}"; do
    if [ -n "${values[$key]}" ] && [ -z "${seen[$key]:-}" ]; then
      env_line "$key" "${values[$key]}"
    fi
  done
}

env_line() {
  [[ "$2" != *$'\n'* ]] || die "$1 holds a line break"
  printf '%s=%s\n' "$1" "$(env_quote "$2")"
}

collect_credentials() {
  step "Setting up the credentials"
  local existing="$ROOT$ENV_PATH" template="$WORK/bundle/backend/.env.example" var
  local -A old=() blank=()
  if [ -n "$ENV_FROM" ]; then
    log INFO "Using $ENV_FROM"
    PASS_ON+=(--env-from "$ENV_FROM")
    return
  fi
  # only a dry run by a normal user can meet a file it may not read
  if [ -f "$existing" ] && [ -r "$existing" ]; then
    load_env "$existing" old
  fi
  if [ -f "$existing" ] && { [ ! -r "$existing" ] || { [ -n "${old[WAZUH_PASS]:-}" ] && [ -n "${old[INDEXER_PASS]:-}" ]; }; }; then
    log INFO "Keeping the existing $existing"
    [ "$CRED_FLAGS" = 0 ] || log WARN "The credential flags are ignored while that file exists; edit it, or pass --env-from"
    return
  fi
  if [ -f "$existing" ]; then
    log WARN "$existing has an empty WAZUH_PASS or INDEXER_PASS, so it is not usable as it stands"
    template="$existing"
    # a value still equal to the template's was never chosen; the example's
    # INDEXER_HOST is the lab's address and must not become the default here
    load_env "$WORK/bundle/backend/.env.example" blank
    for var in WAZUH_HOST WAZUH_PORT WAZUH_USER WAZUH_PASS INDEXER_HOST INDEXER_PORT INDEXER_USER INDEXER_PASS; do
      if [ -z "${!var}" ] && [ "${old[$var]:-}" != "${blank[$var]:-}" ]; then
        printf -v "$var" '%s' "${old[$var]:-}"
      fi
    done
    SNMP_COMMUNITY="${SNMP_COMMUNITY:-${old[VULNMAPPER_SNMP_COMMUNITY]:-}}"
  fi
  if [ "$DRY_RUN" = 1 ]; then
    log INFO "Would ask for the credentials, test them and install them as $existing"
    return
  fi

  local yml="$ROOT$WAZUH_YML" yml_user="" yml_pass=""
  if [ -r "$yml" ]; then
    { IFS= read -r yml_user && IFS= read -r yml_pass; } < <(read_wazuh_yml "$yml") || true
  fi
  WAZUH_HOST="${WAZUH_HOST:-127.0.0.1}" WAZUH_PORT="${WAZUH_PORT:-55000}"
  WAZUH_USER="${WAZUH_USER:-${yml_user:-wazuh-wui}}"
  INDEXER_HOST="${INDEXER_HOST:-127.0.0.1}" INDEXER_PORT="${INDEXER_PORT:-9200}"
  INDEXER_USER="${INDEXER_USER:-admin}"

  # the dashboard's password belongs to the dashboard's user, not to another one
  if [ -z "$WAZUH_PASS" ] && [ "$WAZUH_USER" = "$yml_user" ]; then
    WAZUH_PASS="$yml_pass"
    [ "$YES" = 1 ] || [ -z "$WAZUH_PASS" ] \
      || ask_secret WAZUH_PASS "Wazuh API password for $WAZUH_USER (Enter uses the one in wazuh.yml)"
  fi
  if [ "$YES" = 1 ]; then
    [ -n "$WAZUH_PASS" ] || die "-y needs --wazuh-pass"
    [ -n "$INDEXER_PASS" ] || die "-y needs --indexer-pass"
  fi
  while [ -z "$WAZUH_PASS" ]; do
    ask_secret WAZUH_PASS "Wazuh API password for $WAZUH_USER"
  done
  while [ -z "$INDEXER_PASS" ]; do
    ask_secret INDEXER_PASS "Indexer password for $INDEXER_USER"
  done
  if [ -z "$SNMP_COMMUNITY" ] && [ "$YES" = 0 ]; then
    cat <<'EOF'
SNMP community (optional). Scheduled scans and the liveness check use this one;
the dashboard's scan form can still override it for a single scan.
EOF
    ask_secret SNMP_COMMUNITY "SNMP community (Enter to skip)"
  fi

  until try_wazuh; do
    [ "$YES" = 0 ] || die "the Wazuh API login failed"
    ask WAZUH_HOST "Wazuh API host"
    ask WAZUH_PORT "Wazuh API port"
    ask WAZUH_USER "Wazuh API user"
    ask_secret WAZUH_PASS "Wazuh API password (Enter keeps the last one)"
  done
  until try_indexer; do
    [ "$YES" = 0 ] || die "the indexer login failed"
    ask INDEXER_HOST "Indexer host"
    ask INDEXER_PORT "Indexer port"
    ask INDEXER_USER "Indexer user"
    ask_secret INDEXER_PASS "Indexer password (Enter keeps the last one)"
  done

  install -m 600 /dev/null "$WORK/vulnmapper.env"
  write_env "$template" > "$WORK/vulnmapper.env"
  PASS_ON+=(--env-from "$WORK/vulnmapper.env")
}

run_install() {
  step "Running the installer"
  [ -z "$IMPORT_DATA" ] || PASS_ON+=(--import-data "$IMPORT_DATA")
  [ -z "$SECTION" ] || PASS_ON+=(--section "$SECTION")
  [ "$DRY_RUN" = 0 ] || PASS_ON+=(--dry-run)
  [ -z "$ROOT" ] || PASS_ON+=(--prefix "$ROOT")
  # pip is the one part of the install that wants the network
  if [ -n "$OFFLINE" ] && [ -d "$WORK/bundle/wheels" ]; then
    export PIP_NO_INDEX=1 PIP_FIND_LINKS="$WORK/bundle/wheels"
  fi
  local self
  printf -v self 'bash %q' "$(readlink -f "$0")"
  NTM_BOOTSTRAP="$self" bash "$WORK/bundle/scripts/install-wazuh.sh" "${PASS_ON[@]}" "$SRC/$ZIP" 2>&1 | tee -a "$LOG"
}

run_uninstall() {
  step "Running the uninstaller"
  local opts=()
  [ "$PURGE" = 0 ] || opts+=(--purge)
  [ "$DRY_RUN" = 0 ] || opts+=(--dry-run)
  [ -z "$ROOT" ] || opts+=(--prefix "$ROOT")
  bash "$WORK/bundle/scripts/uninstall-wazuh.sh" "${opts[@]}" 2>&1 | tee -a "$LOG"
}

main() {
  trap 'fail $?' ERR
  # the temp folder can hold a password file, so it must also go on Ctrl-C
  trap 'exit 130' INT TERM HUP
  parse_args "$@"
  check_system
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  if [ "$ACTION" = install ]; then
    read_osd_version
    resolve_release
    fetch_release
    collect_credentials
    # last, so nothing is installed on a machine one of the steps above rejects
    install_packages
    run_install
  else
    resolve_release
    fetch_release
    run_uninstall
  fi
  step "Done"
}

# the tests source this file to reach the credential functions
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  main "$@"
fi
