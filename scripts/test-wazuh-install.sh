#!/bin/bash
# Checks install-wazuh.sh and uninstall-wazuh.sh with --dry-run against a fake
# Wazuh server in a temporary folder: nothing changes, the marked block is
# added once (also on a re-run) and the uninstall gives the original config back.
# No root, no Wazuh needed:  scripts/test-wazuh-install.sh
# shellcheck disable=SC2016,SC2034 # the checks are single-quoted on purpose: check() evals them
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
FAILS=0
ok() { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

F="$T/root"
YML="$F/etc/wazuh-dashboard/opensearch_dashboards.yml"
mkdir -p "$F/usr/share/wazuh-dashboard" "$(dirname "$YML")"
echo '{"name":"opensearch-dashboards","version":"2.19.6"}' > "$F/usr/share/wazuh-dashboard/package.json"
printf 'server.host: 0.0.0.0\nserver.port: 443\nopensearch.hosts: https://127.0.0.1:9200\n\nuiSettings.overrides.defaultRoute: /app/wz-home\n' > "$YML"
cp "$YML" "$T/original.yml"

zip_for() {
  python3 - "$1" "$2" <<'EOF'
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("opensearch-dashboards/vulnmapper/opensearch_dashboards.json",
               json.dumps({"id": "vulnmapper", "opensearchDashboardsVersion": sys.argv[2]}))
EOF
}
zip_for "$T/vulnmapper-2.19.6.zip" 2.19.6
zip_for "$T/vulnmapper-2.19.3.zip" 2.19.3

listing() { (cd "$F" && find . -printf '%p %s %m\n' | sort); }
before="$(listing)"

# an installed config: the original with the block the dry run says it would add
"$HERE/install-wazuh.sh" --dry-run --prefix "$F" "$T/vulnmapper-2.19.6.zip" > "$T/install.out" 2> "$T/install.err"
check "install --dry-run succeeds" '[ $? -eq 0 ] || { cat "$T/install.err"; false; }'
check "install --dry-run changes nothing" '[ "$(listing)" = "$before" ]'
check "it says what it would run" 'grep -q "would run: sudo -u wazuh-dashboard .*opensearch-dashboards-plugin install file:///opt/vulnmapper/vulnmapper-2.19.6.zip" "$T/install.out"'
patch -s -o "$T/installed.yml" "$YML" < "$T/install.out"
check "the block is added once" '[ "$(grep -c "^# BEGIN vulnmapper" "$T/installed.yml")" = 1 ] && [ "$(grep -c "^# END vulnmapper" "$T/installed.yml")" = 1 ]'
check "the original lines are untouched" '[ "$(head -n 5 "$T/installed.yml")" = "$(cat "$T/original.yml")" ]'
check "the block has the settings" 'grep -qx "vulnmapper.graphPath: /var/lib/vulnmapper/graph.json" "$T/installed.yml" && grep -qx "vulnmapper.liveness.autoRescan: false" "$T/installed.yml" && grep -qx "vulnmapper.wazuhCard.section: \"THREAT INTELLIGENCE\"" "$T/installed.yml"'
check "nothing secret in the block" '! grep -Eqi "pass|community|key" "$T/installed.yml"'

# re-run on the installed config: still one block, and the chosen section is kept
cp "$T/installed.yml" "$YML"
sed -i 's/"THREAT INTELLIGENCE"/"ENDPOINT SECURITY"/' "$YML"
cp "$YML" "$T/installed-endpoint.yml"
"$HERE/install-wazuh.sh" --dry-run --prefix "$F" "$T/vulnmapper-2.19.6.zip" > "$T/rerun.out" 2>/dev/null
patch -s -o "$T/rerun.yml" "$YML" < "$T/rerun.out" 2>/dev/null || cp "$YML" "$T/rerun.yml"
check "a re-run keeps one block" '[ "$(grep -c "^# BEGIN vulnmapper" "$T/rerun.yml")" = 1 ]'
check "a re-run keeps the chosen section" 'cmp -s "$T/rerun.yml" "$T/installed-endpoint.yml"'
"$HERE/install-wazuh.sh" --dry-run --prefix "$F" --section "SECURITY OPERATIONS" "$T/vulnmapper-2.19.6.zip" > "$T/section.out" 2>/dev/null
check "--section moves the card" 'grep -qx "+vulnmapper.wazuhCard.section: \"SECURITY OPERATIONS\"" "$T/section.out"'

# uninstall: the original back, byte for byte
"$HERE/uninstall-wazuh.sh" --dry-run --prefix "$F" > "$T/uninstall.out" 2>&1
check "uninstall --dry-run succeeds" '[ $? -eq 0 ]'
check "uninstall --dry-run changes nothing" 'cmp -s "$YML" "$T/installed-endpoint.yml"'
patch -s -o "$T/uninstalled.yml" "$YML" < "$T/uninstall.out"
check "uninstall removes the block cleanly" 'cmp -s "$T/uninstalled.yml" "$T/original.yml"'
check "uninstall keeps data and credentials" '! grep -q "rm -rf .*\(/var/lib/vulnmapper\|/etc/vulnmapper\)" "$T/uninstall.out"'
"$HERE/uninstall-wazuh.sh" --dry-run --prefix "$F" --purge > "$T/purge.out" 2>&1
check "--purge removes them" 'grep -q "would run: rm -rf .*/var/lib/vulnmapper .*/etc/vulnmapper" "$T/purge.out"'

# refusals
cp "$T/original.yml" "$YML"
"$HERE/install-wazuh.sh" --dry-run --prefix "$F" "$T/vulnmapper-2.19.3.zip" > /dev/null 2> "$T/mismatch.err"
check "a zip for another dashboard version is refused" '[ $? -ne 0 ] && grep -q "built for dashboard 2.19.3 but this one is 2.19.6" "$T/mismatch.err"'
echo "vulnmapper.graphPath: /somewhere/graph.json" >> "$YML"
"$HERE/install-wazuh.sh" --dry-run --prefix "$F" "$T/vulnmapper-2.19.6.zip" > /dev/null 2> "$T/dup.err"
check "vulnmapper settings outside the block are refused" '[ $? -ne 0 ] && grep -q "outside" "$T/dup.err"'
cp "$T/original.yml" "$YML"
"$HERE/install-wazuh.sh" --dry-run --prefix "$F" --section 'X"; rm -rf /' "$T/vulnmapper-2.19.6.zip" > /dev/null 2>&1
check "an odd section name is refused" '[ $? -ne 0 ]'

if command -v shellcheck > /dev/null; then
  check "shellcheck" 'shellcheck -x "$HERE/install-wazuh.sh" "$HERE/uninstall-wazuh.sh" "$HERE/wazuh-lib.sh" "$0"'
else
  printf 'skip  shellcheck (not installed)\n'
fi

if [ "$FAILS" != 0 ]; then echo "$FAILS failed"; exit 1; fi
echo "all passed"
