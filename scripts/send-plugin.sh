#!/bin/bash
# Build the plugin zip on the development machine and copy it to the server.
SERVER="${VULNMAPPER_SERVER:-wazuh-server@172.20.40.1}"
. "$(dirname "${BASH_SOURCE[0]}")/osd-version.sh"
set -e
build_plugin_zip "$OSD_VERSION"
scp "$PLUGIN_DIR/build/vulnmapper-$OSD_VERSION.zip" "$SERVER":~/
echo "Sent. On the server run scripts/update-plugin.sh (plain dashboard in ~/osd),"
echo "or for the Wazuh dashboard: sudo scripts/install-wazuh.sh ~/vulnmapper-$OSD_VERSION.zip"
