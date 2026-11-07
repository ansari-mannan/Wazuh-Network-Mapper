# The OpenSearch Dashboards version the plugin is built for and runs on, in
# one place for run.sh and the build scripts. OSD_VERSION in the environment
# overrides it, e.g. OSD_VERSION=2.19.6 for the Wazuh dashboard 4.14.8; the
# zip (build/vulnmapper-<version>.zip) installs only into that exact version.
OSD_VERSION="${OSD_VERSION:-2.19.3}"

PLUGIN_DIR=~/dev/OpenSearch-Dashboards/plugins/vulnmapper

# build_plugin_zip VERSION: leaves build/vulnmapper-VERSION.zip in PLUGIN_DIR.
# A subshell, because nvm does not work under the caller's set -eu.
build_plugin_zip() (
  set +eu
  . ~/.nvm/nvm.sh
  nvm use 18.19.0 || exit 1
  set -e
  cd "$PLUGIN_DIR"
  yarn build --opensearch-dashboards-version "$1"
)
