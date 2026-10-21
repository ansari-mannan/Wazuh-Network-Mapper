# The OpenSearch Dashboards version the plugin is built for and runs on, in
# one place for run.sh and the build scripts. OSD_VERSION in the environment
# overrides it, e.g. OSD_VERSION=2.19.6 for the Wazuh dashboard 4.14.8; the
# zip (build/vulnmapper-<version>.zip) installs only into that exact version.
OSD_VERSION="${OSD_VERSION:-2.19.3}"
