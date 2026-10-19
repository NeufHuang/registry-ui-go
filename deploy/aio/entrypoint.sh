#!/bin/sh
set -eu

: "${DEPLOY_MODE:=aio}"
: "${REGISTRY_CONFIG:=/etc/distribution/config.yml}"
: "${SERVER_ADDR:=:8080}"
: "${REGISTRY_URL:=http://127.0.0.1:5000}"
: "${DATA_DIR:=/data}"
: "${SQLITE_PATH:=/data/db/registry-ui.db}"
: "${UPLOAD_DIR:=/data/uploads}"
: "${CERT_DIR:=/data/certs}"
: "${REGISTRY_DATA_DIR:=/data/registry}"
: "${ENABLE_DELETE:=true}"

# Do NOT export the REGISTRY_* variables globally. distribution/registry maps
# every REGISTRY_-prefixed variable onto its own config tree, so a global
# REGISTRY_DATA_DIR is read as storage.data.dir and REGISTRY_URL as http.url,
# silently overriding registry-config.yml. That makes `registry garbage-collect`
# mark the wrong path (/docker/registry/v2/repositories) and fail. They are
# handed to the UI process only, through the scoped assignment at its launch.
export DEPLOY_MODE SERVER_ADDR DATA_DIR SQLITE_PATH UPLOAD_DIR CERT_DIR ENABLE_DELETE

# Fix permissions when running as root (e.g. volume mounted from host)
if [ "$(id -u)" = "0" ]; then
  mkdir -p /data/db /data/certs /data/uploads "$REGISTRY_DATA_DIR"
  # registry 3.x resolves storage paths against an existing tree; if the v2
  # directory layout is missing, `registry garbage-collect` fails with
  # "Path not found: /docker/registry/v2/repositories" even though the config
  # is correct. Pre-create the layout on a fresh volume to avoid that.
  mkdir -p "$REGISTRY_DATA_DIR/docker/registry/v2/repositories" \
           "$REGISTRY_DATA_DIR/docker/registry/v2/blobs"
  chown -R registry-ui:registry-ui /data /etc/distribution
  # Re-exec as non-root user
  exec su-exec registry-ui "$0" "$@"
fi

# From here on we run as registry-ui (UID 10001)
mkdir -p /data/db /data/certs /data/uploads "$REGISTRY_DATA_DIR"
mkdir -p "$REGISTRY_DATA_DIR/docker/registry/v2/repositories" \
         "$REGISTRY_DATA_DIR/docker/registry/v2/blobs"

if [ "$DEPLOY_MODE" = "aio" ]; then
  registry serve "$REGISTRY_CONFIG" &
  registry_pid=$!
fi

# The UI needs the REGISTRY_* variables; pass them only to this child process.
env \
  REGISTRY_CONFIG="$REGISTRY_CONFIG" \
  REGISTRY_URL="$REGISTRY_URL" \
  REGISTRY_DATA_DIR="$REGISTRY_DATA_DIR" \
  /usr/local/bin/registry-ui &
ui_pid=$!

shutdown() {
  kill "$ui_pid" 2>/dev/null || true
  if [ "$DEPLOY_MODE" = "aio" ]; then
    kill "$registry_pid" 2>/dev/null || true
  fi
}
trap shutdown INT TERM EXIT

wait "$ui_pid"
code=$?
if [ "$DEPLOY_MODE" = "aio" ]; then
  kill "$registry_pid" 2>/dev/null || true
  wait "$registry_pid" 2>/dev/null || true
fi
exit "$code"
