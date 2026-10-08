#!/bin/bash
# On the server: reinstall the plugin from the copied zip, then start the dashboard.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSD_VERSION="${OSD_VERSION:-2.19.3}"
OSD_HOME="${OSD_HOME:-$HOME/osd}"
pkill -f "$OSD_HOME/node/bin/node" && sleep 3
set -e
cd "$OSD_HOME"
./bin/opensearch-dashboards-plugin remove vulnmapper || true
./bin/opensearch-dashboards-plugin install "file://$HOME/vulnmapper-$OSD_VERSION.zip"
exec "$HERE/run.sh"
