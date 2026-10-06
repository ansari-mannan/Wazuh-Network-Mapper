#!/bin/bash
# Build the plugin zip on the development machine and copy it to the server.
SERVER="${VULNMAPPER_SERVER:-wazuh-server@172.20.40.1}"
OSD_VERSION="${OSD_VERSION:-2.19.3}"
source ~/.nvm/nvm.sh
nvm use 18.19.0
set -e
cd ~/dev/OpenSearch-Dashboards/plugins/vulnmapper
yarn build --opensearch-dashboards-version "$OSD_VERSION"
scp "build/vulnmapper-$OSD_VERSION.zip" "$SERVER":~/
echo "Sent. Now run scripts/update-plugin.sh on the server."
