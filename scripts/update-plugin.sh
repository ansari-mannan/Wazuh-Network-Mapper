#!/bin/bash
# On the server: reinstall the plugin from the copied zip and restart the dashboard.
OSD_VERSION="${OSD_VERSION:-2.19.3}"
pkill -f "$HOME/osd/node/bin/node" && sleep 3
set -e
cd ~/osd
./bin/opensearch-dashboards-plugin remove vulnmapper || true
./bin/opensearch-dashboards-plugin install "file://$HOME/vulnmapper-$OSD_VERSION.zip"
set -a; . ~/.vulnmapper.env; set +a
exec ./bin/opensearch-dashboards
