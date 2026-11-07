#!/bin/bash
# Checks ntm-install.sh with --offline --dry-run --prefix against a fake release
# folder and a fake Wazuh server in a temporary folder, plus the online path and
# the credential step with a fake curl on PATH (--dry-run skips that step, so the
# test sources the script to reach it). No root, no Wazuh, no network needed:
#   scripts/test-ntm-install.sh
# shellcheck disable=SC2016,SC2034,SC1090,SC1091 # the checks are single-quoted on purpose: check() evals them
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOT="$HERE/ntm-install.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
FAILS=0
ok() { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
ZIP_MSG="would run: sudo -u wazuh-dashboard .*opensearch-dashboards-plugin install file:///opt/vulnmapper/vulnmapper-2.19.6.zip"

# the fake server
F="$T/root"
YML="$F/etc/wazuh-dashboard/opensearch_dashboards.yml"
mkdir -p "$F/usr/share/wazuh-dashboard" "$(dirname "$YML")"
echo '{"name":"opensearch-dashboards","version":"2.19.6"}' > "$F/usr/share/wazuh-dashboard/package.json"
printf 'server.host: 0.0.0.0\nserver.port: 443\n' > "$YML"

# the fake release: the real scripts, a plugin zip for 2.19.6 and one for 2.19.3
zip_for() {
  python3 - "$1" "$2" <<'EOF'
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("opensearch-dashboards/vulnmapper/opensearch_dashboards.json",
               json.dumps({"id": "vulnmapper", "opensearchDashboardsVersion": sys.argv[2]}))
EOF
}
R="$T/release"
mkdir -p "$R"
tar -C "$HERE/.." -czf "$R/ntm-v9.9.9.tar.gz" backend/.env.example backend/requirements.txt \
  scripts/install-wazuh.sh scripts/uninstall-wazuh.sh scripts/wazuh-lib.sh
zip_for "$R/vulnmapper-2.19.6.zip" 2.19.6
zip_for "$R/vulnmapper-2.19.3.zip" 2.19.3
(cd "$R" && sha256sum ./*.tar.gz ./*.zip | sed 's| \./| |' > SHA256SUMS)

listing() { (cd "$F" && find . -printf '%p %s %m\n' | sort); }
before="$(listing)"
export TMPDIR="$T/tmp"
mkdir -p "$TMPDIR"
boot() { bash "$BOOT" "$@" --prefix "$F" --dry-run -y; }

# a matching zip goes to install-wazuh.sh
boot -i --offline "$R" > "$T/ok.out" 2>&1
check "--offline --dry-run succeeds" '[ $? -eq 0 ] || { cat "$T/ok.out"; false; }'
check "the matching zip reaches install-wazuh.sh" 'grep -q "$ZIP_MSG" "$T/ok.out"'
check "the status lines are timestamped" 'grep -Eq "^[0-9/]+ [0-9:]+ INFO: Reading the dashboard version" "$T/ok.out"'
check "the summary names the bootstrap, not the temp folder" 'grep -q "To move the card: sudo bash .*ntm-install.sh -i --section \"ENDPOINT SECURITY\"" "$T/ok.out" && ! grep -q "To move the card: .*install-wazuh" "$T/ok.out"'
check "the block names the bootstrap" 'grep -q "managed by ntm-install.sh" "$T/ok.out"'
check "packages come after the checks, before the installer" 'grep -E "INFO: (Fetching|Setting up|Checking required|Running the)" "$T/ok.out" | sed "s/.*INFO: //" | tr "\n" , | grep -qx "Fetching and checking the files,Setting up the credentials,Checking required packages,Running the installer,"'
check "the dry run changes nothing" '[ "$(listing)" = "$before" ]'
check "the temp folder is gone" '[ -z "$(ls -A "$TMPDIR")" ]'
check "a first dry run asks for nothing" 'grep -q "Would ask for the credentials" "$T/ok.out"'
"$HERE/install-wazuh.sh" --dry-run --prefix "$F" "$R/vulnmapper-2.19.6.zip" > "$T/direct.out" 2>&1
check "run directly it still names itself" 'grep -q "To move the card: sudo .*install-wazuh.sh --section \"ENDPOINT SECURITY\" <zip>" "$T/direct.out" && grep -q "managed by scripts/install-wazuh.sh" "$T/direct.out"'

# options reach install-wazuh.sh
boot -i --offline "$R" --section "SECURITY OPERATIONS" --env-from "$T/ok.out" > "$T/opts.out" 2>&1
check "--section is passed on" 'grep -qx "+vulnmapper.wazuhCard.section: \"SECURITY OPERATIONS\"" "$T/opts.out"'
check "--env-from is passed on" 'grep -q "Copying $T/ok.out to" "$T/opts.out"'
check "--env-from skips the credentials" '! grep -q "Would ask" "$T/opts.out"'

# no zip for this dashboard
echo '{"version":"2.19.9"}' > "$F/usr/share/wazuh-dashboard/package.json"
boot -i --offline "$R" > "$T/nozip.out" 2>&1
check "no zip for the version is refused" '[ $? -ne 0 ]'
check "it lists the versions there are" 'grep -q "no plugin for dashboard 2.19.9. It has: 2.19.3 2.19.6" "$T/nozip.out"'
check "install-wazuh.sh never runs" '! grep -q "Running the installer" "$T/nozip.out"'
check "it names the step" 'grep -q "Stopped at: Finding the release" "$T/nozip.out"'
check "no packages are touched when the zip is missing" '! grep -q "Checking required packages" "$T/nozip.out"'
echo '{"name":"opensearch-dashboards","version":"2.19.6"}' > "$F/usr/share/wazuh-dashboard/package.json"

# checksums
cp -r "$R" "$T/bad"
echo x >> "$T/bad/vulnmapper-2.19.6.zip"
boot -i --offline "$T/bad" > "$T/sum.out" 2>&1
check "a changed zip is refused" '[ $? -ne 0 ] && grep -q "Checksum mismatch for vulnmapper-2.19.6.zip" "$T/sum.out"'
check "install-wazuh.sh does not run on it" '! grep -q "Running the installer" "$T/sum.out"'
check "no packages are touched on a bad checksum" '! grep -q "Checking required packages" "$T/sum.out"'
check "the temp folder is gone after a failure" '[ -z "$(ls -A "$TMPDIR")" ]'
cp "$R/vulnmapper-2.19.6.zip" "$T/bad/"
sed -i '/vulnmapper-2.19.6.zip/d' "$T/bad/SHA256SUMS"
boot -i --offline "$T/bad" > "$T/unlisted.out" 2>&1
check "a file missing from SHA256SUMS is refused" '[ $? -ne 0 ] && grep -q "not listed in SHA256SUMS" "$T/unlisted.out"'
rm "$T/bad/SHA256SUMS"
boot -i --offline "$T/bad" > "$T/nosums.out" 2>&1
check "a folder without SHA256SUMS is refused" '[ $? -ne 0 ] && grep -q "no SHA256SUMS" "$T/nosums.out"'

# an existing env file is kept
ENVF="$F/etc/vulnmapper/vulnmapper.env"
mkdir -p "$(dirname "$ENVF")"
printf 'WAZUH_PASS=keep-me\nINDEXER_PASS=me-too\n' > "$ENVF"
sum_before="$(sha256sum "$ENVF")"
boot -i --offline "$R" --wazuh-pass other > "$T/keep.out" 2>&1
check "a re-run succeeds" '[ $? -eq 0 ] || { cat "$T/keep.out"; false; }'
check "a filled env file is kept, same hash" 'grep -q "Keeping the existing" "$T/keep.out" && [ "$(sha256sum "$ENVF")" = "$sum_before" ]'
check "nothing is copied over it" '! grep -q "would run: cp .*vulnmapper.env\|Copying .* to $ENVF" "$T/keep.out"'
check "ignored credential flags are mentioned" 'grep -q "credential flags are ignored" "$T/keep.out"'
cp "$HERE/../backend/.env.example" "$ENVF"
boot -i --offline "$R" > "$T/blank.out" 2>&1
check "a blank env file is not kept" '[ $? -eq 0 ] && grep -q "empty WAZUH_PASS or INDEXER_PASS" "$T/blank.out" && grep -q "Would ask for the credentials" "$T/blank.out" && ! grep -q "Keeping the existing" "$T/blank.out"'
rm -r "$F/etc/vulnmapper"

# uninstall
boot -u --offline "$R" > "$T/un.out" 2>&1
check "uninstall succeeds" '[ $? -eq 0 ] || { cat "$T/un.out"; false; }'
check "uninstall keeps data and credentials" 'grep -q "would run: rm -rf .*/opt/vulnmapper" "$T/un.out" && ! grep -q "rm -rf .*/var/lib/vulnmapper" "$T/un.out"'
boot -u --purge --offline "$R" > "$T/purge.out" 2>&1
check "--purge is passed on" 'grep -q "would run: rm -rf .*/var/lib/vulnmapper .*/etc/vulnmapper" "$T/purge.out"'
rm "$F/usr/share/wazuh-dashboard/package.json"
boot -u --offline "$R" > "$T/nodash.out" 2>&1
check "uninstall needs no dashboard version" '[ $? -eq 0 ]'
boot -i --offline "$R" > "$T/nodash.out" 2>&1
check "install stops without a dashboard" '[ $? -ne 0 ] && grep -q "No Wazuh dashboard" "$T/nodash.out"'
echo '{"name":"opensearch-dashboards","version":"2.19.6"}' > "$F/usr/share/wazuh-dashboard/package.json"

# refusals
cp "$R/ntm-v9.9.9.tar.gz" "$T/ntm-v9.9.8.tar.gz"
cp -r "$R" "$T/two" && cp "$T/ntm-v9.9.8.tar.gz" "$T/two/"
boot -i --offline "$T/two" > "$T/two.out" 2>&1
check "two bundles need --version" '[ $? -ne 0 ] && grep -q "pick one with --version" "$T/two.out"'
boot -i --offline "$T/two" --version v9.9.9 > "$T/two.out" 2>&1
check "--version picks one" '[ $? -eq 0 ]'
bash "$BOOT" --dry-run > /dev/null 2>&1
check "no -i or -u is refused" '[ $? -ne 0 ]'
boot -i --purge --offline "$R" > /dev/null 2>&1
check "--purge without -u is refused" '[ $? -ne 0 ]'
boot -i -u --offline "$R" > /dev/null 2>&1
check "-i with -u is refused" '[ $? -ne 0 ]'
boot -i --version '../x' --offline "$R" > /dev/null 2>&1
check "an odd tag is refused" '[ $? -ne 0 ]'
if [ "$(id -u)" != 0 ]; then
  bash "$BOOT" -i --offline "$R" --prefix "$F" -y > "$T/root.out" 2>&1
  check "a real run needs root" '[ $? -ne 0 ] && grep -q "Run this with sudo" "$T/root.out"'
fi

# a fake curl: GitHub answers from the release folder, the logins as CODE_* say
mkdir "$T/bin"
cat > "$T/bin/curl" <<'EOF'
#!/bin/bash
echo "$*" >> "$FAKE/argv"
out=/dev/null url="" login=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -K) login="$(cat)"; echo "$login" >> "$FAKE/stdin"; shift 2 ;;
    -w|-m|-H|-X|--retry) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://api.github.com/*/releases/latest) cat "$FAKE/release.json" > "$out"; printf '%s' "${CODE_API:-200}" ;;
  https://api.github.com/*/tags/*) printf 404 ;;
  https://github.com/*) cp "$R/$(basename "$url")" "$out" ;;
  */security/user/authenticate) case "$login" in *WRONG*) printf 401 ;; *) printf '%s' "${CODE_WAZUH:-200}" ;; esac ;;
  *) printf '%s' "${CODE_INDEXER:-200}" ;;
esac
EOF
chmod +x "$T/bin/curl"
export FAKE="$T/fake" R
mkdir "$FAKE"
python3 - "$R" > "$FAKE/release.json" <<'EOF'
import json, os, sys
print(json.dumps({"tag_name": "v9.9.9", "assets": [{"name": n} for n in os.listdir(sys.argv[1])]}))
EOF
export PATH="$T/bin:$PATH"

boot -i > "$T/online.out" 2>&1
check "the online path finds the latest release" '[ $? -eq 0 ] && grep -q "Using release v9.9.9" "$T/online.out" && grep -q "$ZIP_MSG" "$T/online.out"'
CODE_API=404 boot -i > "$T/none.out" 2>&1
check "no release yet is said plainly" '[ $? -ne 0 ] && grep -q "No release published yet" "$T/none.out"'
boot -i --version v0 > "$T/notag.out" 2>&1
check "an unknown tag is said plainly" '[ $? -ne 0 ] && grep -q "No release v0" "$T/notag.out"'

# the credential step, reached by sourcing the script. creds SETUP: runs it as
# on a first install, with the template of the repo, and leaves the env in $W.
W="$T/work"
mkdir -p "$W/bundle/backend"
cp "$HERE/../backend/.env.example" "$W/bundle/backend/"
creds() {
  rm -f "$W/vulnmapper.env" "$FAKE/argv" "$FAKE/stdin"
  ( . "$BOOT"; WORK="$W" ROOT="$F"; eval "$1"; collect_credentials; printf 'PASS_ON=%s\n' "${PASS_ON[*]}" )
}
PW='a"b\c$d`e'"'"'f #g h'
creds 'YES=1 WAZUH_PASS="$PW" INDEXER_PASS="$PW" SNMP_COMMUNITY=" my, comm "' > "$T/cred.out" 2>&1
check "good logins pass" '[ $? -eq 0 ] || { cat "$T/cred.out"; false; }'
check "the env file is handed on" 'grep -q "PASS_ON=--env-from $W/vulnmapper.env" "$T/cred.out"'
check "the env file is mode 600" '[ "$(stat -c %a "$W/vulnmapper.env")" = 600 ]'
check "it has exactly the variables of .env.example" '[ "$(grep -oE "^[A-Z0-9_]+=" "$W/vulnmapper.env")" = "$(grep -oE "^[A-Z0-9_]+=" "$HERE/../backend/.env.example")" ]'
check "the defaults are the local ones" 'grep -qx "WAZUH_HOST=\"127.0.0.1\"" "$W/vulnmapper.env" && grep -qx "INDEXER_HOST=\"127.0.0.1\"" "$W/vulnmapper.env" && grep -qx "INDEXER_USER=\"admin\"" "$W/vulnmapper.env" && grep -qx "WAZUH_USER=\"wazuh-wui\"" "$W/vulnmapper.env"'
got() { ( set -a; . "$W/vulnmapper.env"; printf '%s' "$(eval "printf %s \"\${$1}\"")" ); }
check "an awkward password comes back exactly" '[ "$(got WAZUH_PASS)" = "$PW" ]'
check "the community keeps its spaces" '[ "$(got VULNMAPPER_SNMP_COMMUNITY)" = " my, comm " ]'
check "TLS verification stays off" 'grep -qx "VULNMAPPER_VERIFY_TLS=" "$W/vulnmapper.env"'
check "the password is not on curl's command line" '! grep -qF "a\"b" "$FAKE/argv"'
check "the login tests skip TLS checks" '[ "$(grep -c -- "-k" "$FAKE/argv")" = 2 ]'
check "curl gets the password escaped" 'grep -qF "user = \"wazuh-wui:a\\\"b\\\\c" "$FAKE/stdin"'
creds 'YES=1 WAZUH_PASS=x INDEXER_PASS=y VERIFY_TLS=1' > /dev/null 2>&1
check "--verify-tls is written and used" 'grep -qx "VULNMAPPER_VERIFY_TLS=\"true\"" "$W/vulnmapper.env" && ! grep -q -- " -k" "$FAKE/argv"'

CODE_WAZUH=401 creds 'YES=1 WAZUH_PASS=x INDEXER_PASS=y' > "$T/refused.out" 2>&1
check "-y fails on a refused login" '[ $? -ne 0 ] && grep -q "refused the user or password" "$T/refused.out" && [ ! -e "$W/vulnmapper.env" ]'
CODE_INDEXER=000 creds 'YES=1 WAZUH_PASS=x INDEXER_PASS=y' > "$T/down.out" 2>&1
check "-y fails when the indexer does not answer" '[ $? -ne 0 ] && grep -q "No answer from the Wazuh indexer" "$T/down.out"'
creds 'YES=1 INDEXER_PASS=y' > "$T/miss.out" 2>&1
check "-y fails on a missing password" '[ $? -ne 0 ] && grep -q "needs --wazuh-pass" "$T/miss.out"'
creds 'YES=1 WAZUH_PASS=x INDEXER_PASS=y WAZUH_HOST="a/b"' > "$T/host.out" 2>&1
check "an odd host is refused" '[ $? -ne 0 ] && grep -q "Not a host and port" "$T/host.out"'

# the API user and password of the dashboard's wazuh.yml
WY="$F/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
mkdir -p "$(dirname "$WY")"
cat > "$WY" <<'EOF'
# hosts:
#   - example:
#       username: not-this
#       password: not-this
hosts:
  - default:
      url: https://127.0.0.1
      port: 55000
      username: wazuh-api
      password: "from \"yml\" #1"
      run_as: false
  - other:
      username: second
      password: second
EOF
creds 'YES=1 INDEXER_PASS=y' > "$T/yml.out" 2>&1
check "wazuh.yml supplies the API login" '[ $? -eq 0 ] && [ "$(got WAZUH_USER)" = wazuh-api ] && [ "$(got WAZUH_PASS)" = "from \"yml\" #1" ]'
creds 'YES=1 INDEXER_PASS=y WAZUH_USER=someone' > "$T/yml2.out" 2>&1
check "its password is not used for another user" '[ $? -ne 0 ] && grep -q "needs --wazuh-pass" "$T/yml2.out"'
printf '\ntyped\nmycomm\n' | creds '' > "$T/ask.out" 2>&1
check "prompts: Enter takes wazuh.yml, the rest as typed" '[ $? -eq 0 ] && [ "$(got WAZUH_PASS)" = "from \"yml\" #1" ] && [ "$(got INDEXER_PASS)" = typed ] && [ "$(got VULNMAPPER_SNMP_COMMUNITY)" = mycomm ]'
rm "$WY"

# an env file that exists but lacks a password, as install-wazuh.sh leaves it
ENVF="$F/etc/vulnmapper/vulnmapper.env"
mkdir -p "$(dirname "$ENVF")"
sed 's/^NVD_API_KEY=$/NVD_API_KEY=abc123/' "$HERE/../backend/.env.example" > "$ENVF"
sum_before="$(sha256sum "$ENVF")"
printf 'wp\nip\n\n' | creds '' > "$T/blank.out" 2>&1
check "blank template: asks and passes the result on" '[ $? -eq 0 ] && grep -q "empty WAZUH_PASS or INDEXER_PASS" "$T/blank.out" && grep -q "PASS_ON=--env-from $W/vulnmapper.env" "$T/blank.out" && [ "$(got WAZUH_PASS)" = wp ] && [ "$(got INDEXER_PASS)" = ip ]'
check "blank template: the logins are tested" 'grep -q "https://127.0.0.1:55000/security/user/authenticate" "$FAKE/argv" && grep -q "https://127.0.0.1:9200/" "$FAKE/argv"'
check "blank template: the example values do not stick" '[ "$(got INDEXER_HOST)" = 127.0.0.1 ] && [ "$(got WAZUH_HOST)" = 127.0.0.1 ] && ! grep -q 192.168.100.2 "$W/vulnmapper.env"'
check "blank template: other settings stay" '[ "$(got NVD_API_KEY)" = abc123 ] && grep -q "^# --- TLS ---" "$W/vulnmapper.env"'
check "blank template: the file itself is left to the installer" '[ "$(sha256sum "$ENVF")" = "$sum_before" ]'
creds 'YES=1' > "$T/blanky.out" 2>&1
check "blank template with -y fails clearly" '[ $? -ne 0 ] && grep -q "needs --wazuh-pass" "$T/blanky.out" && [ ! -e "$W/vulnmapper.env" ]'

cat > "$ENVF" <<'EOF'
# ours
WAZUH_HOST=10.0.0.5
WAZUH_USER=custom
WAZUH_PASS="a\"b\$c"
export INDEXER_HOST='10.0.0.6'
INDEXER_PASS=
SNMP_V3_USER=keepme
EOF
creds 'YES=1' > "$T/part.out" 2>&1
check "half-filled with -y names what is missing" '[ $? -ne 0 ] && grep -q "needs --indexer-pass" "$T/part.out"'
printf 'ip\n\n' | creds '' > "$T/part.out" 2>&1
check "half-filled: only the missing password is asked" '[ $? -eq 0 ] && [ "$(got INDEXER_PASS)" = ip ] && [ "$(got WAZUH_PASS)" = "a\"b\$c" ]'
check "half-filled: its values are the defaults" '[ "$(got WAZUH_USER)" = custom ] && [ "$(got INDEXER_HOST)" = 10.0.0.6 ] && grep -q "https://10.0.0.5:55000/" "$FAKE/argv" && grep -q "https://10.0.0.6:9200/" "$FAKE/argv"'
check "half-filled: other lines stay, missing ones are added" 'grep -qx "SNMP_V3_USER=keepme" "$W/vulnmapper.env" && grep -qx "# ours" "$W/vulnmapper.env" && [ "$(got INDEXER_PORT)" = 9200 ]'
creds 'YES=1 INDEXER_PASS=flag INDEXER_HOST=10.0.0.7' > /dev/null 2>&1
check "half-filled: flags beat the file" '[ "$(got INDEXER_PASS)" = flag ] && [ "$(got INDEXER_HOST)" = 10.0.0.7 ]'
printf 'WAZUH_PASS=x\nINDEXER_PASS=y\n' > "$ENVF"
sum_before="$(sha256sum "$ENVF")"
creds 'YES=1' > "$T/filled.out" 2>&1
check "filled file: kept, same hash, no logins, not passed on" '[ $? -eq 0 ] && grep -q "Keeping the existing" "$T/filled.out" && [ "$(sha256sum "$ENVF")" = "$sum_before" ] && [ ! -e "$FAKE/argv" ] && grep -qx "PASS_ON=" "$T/filled.out"'
rm -r "$F/etc/vulnmapper"

# a refused login is asked again: Enter keeps the host, port and user
printf 'WRONG\nindexer\n\n\n\n\nright\n' | creds '' > "$T/retry.out" 2>&1
check "a refused login is asked again" '[ $? -eq 0 ] && grep -q "refused the user or password" "$T/retry.out" && [ "$(got WAZUH_PASS)" = right ] && [ "$(got WAZUH_HOST)" = 127.0.0.1 ]'
: | creds '' > "$T/notty.out" 2>&1
check "without a terminal it says so instead of hanging" '[ $? -ne 0 ] && grep -q "no terminal to ask on" "$T/notty.out"'

if command -v shellcheck > /dev/null; then
  check "shellcheck" 'shellcheck -x "$BOOT" "$HERE/build-release.sh" "$0"'
else
  printf 'skip  shellcheck (not installed)\n'
fi

if [ "$FAILS" != 0 ]; then echo "$FAILS failed"; exit 1; fi
echo "all passed"
