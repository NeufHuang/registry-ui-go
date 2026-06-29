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

export DEPLOY_MODE REGISTRY_CONFIG SERVER_ADDR REGISTRY_URL DATA_DIR SQLITE_PATH UPLOAD_DIR CERT_DIR REGISTRY_DATA_DIR ENABLE_DELETE

# Fix permissions when running as root (e.g. volume mounted from host)
if [ "$(id -u)" = "0" ]; then
  mkdir -p /data/db /data/certs /data/uploads "$REGISTRY_DATA_DIR"
  chown -R registry-ui:registry-ui /data /etc/distribution
  # Re-exec as non-root user
  exec su-exec registry-ui "$0" "$@"
fi

# From here on we run as registry-ui (UID 10001)
mkdir -p /data/db /data/certs /data/uploads "$REGISTRY_DATA_DIR"

if [ "$DEPLOY_MODE" = "aio" ]; then
  registry serve "$REGISTRY_CONFIG" &
  registry_pid=$!
fi

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
