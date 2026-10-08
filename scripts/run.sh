#!/bin/bash
# Start the dashboard with the VulnMapper plugin.
# Works on a development machine (dashboard run from source) and on a server
# (packaged dashboard). It picks the mode from what is installed.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OSD_HOME="${OSD_HOME:-$HOME/osd}"
OSD_SRC="${OSD_SRC:-$(dirname "$REPO")/OpenSearch-Dashboards}"
OSD_VERSION="${OSD_VERSION:-2.19.3}"
ENV_FILE="${VULNMAPPER_ENV:-$HOME/.vulnmapper.env}"

DOCKER="docker"
docker ps >/dev/null 2>&1 || DOCKER="sudo docker"

start_db() {
  local name="$1" port="$2"
  if $DOCKER ps -a --format '{{.Names}}' | grep -qx "$name"; then
    $DOCKER start "$name" >/dev/null
  else
    echo "Creating database container $name on port $port"
    $DOCKER run -d --name "$name" --restart unless-stopped -p "127.0.0.1:$port:9200" \
      -e "discovery.type=single-node" -e "DISABLE_SECURITY_PLUGIN=true" \
      -e "DISABLE_INSTALL_DEMO_CONFIG=true" -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
      "opensearchproject/opensearch:$OSD_VERSION" >/dev/null || return 1
  fi
  printf "Waiting for the database on port %s " "$port"
  for _ in $(seq 1 90); do
    if curl -s -o /dev/null "http://127.0.0.1:$port"; then echo " ready"; return 0; fi
    printf "."; sleep 2
  done
  echo " not answering after 3 minutes"; return 1
}

load_env() {
  if [ -f "$ENV_FILE" ]; then set -a; . "$ENV_FILE"; set +a; echo "Loaded settings from $ENV_FILE"; fi
}

if [ -x "$OSD_HOME/bin/opensearch-dashboards" ]; then
  echo "Server mode: packaged dashboard in $OSD_HOME"
  pkill -f "$OSD_HOME/node/bin/node" && sleep 3
  start_db osd-db 9201 || exit 1
  load_env
  cd "$OSD_HOME" && exec ./bin/opensearch-dashboards
elif [ -d "$OSD_SRC" ]; then
  echo "Development mode: dashboard source in $OSD_SRC"
  if ss -tln 2>/dev/null | grep -q ':5601 '; then
    echo "A dashboard is already running on port 5601. Open http://localhost:5601/app/vulnmapper"; exit 0
  fi
  MOUNT="$OSD_SRC/plugins/vulnmapper"
  if ! mountpoint -q "$MOUNT"; then
    echo "Connecting the plugin folder (needs sudo)"
    mkdir -p "$MOUNT" && sudo mount --bind "$REPO/plugin" "$MOUNT" || exit 1
  fi
  start_db opensearch 9200 || exit 1
  load_env
  . "$HOME/.nvm/nvm.sh" && nvm use 18.19.0 >/dev/null || exit 1
  cd "$OSD_SRC" && exec yarn start --no-base-path
else
  echo "No dashboard found. Expected a packaged one in $OSD_HOME or the source in $OSD_SRC."
  exit 1
fi
