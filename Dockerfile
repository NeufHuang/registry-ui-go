# Unified image: Registry UI + distribution/registry:3 in one image.
# Use DEPLOY_MODE=aio for single-container, or DEPLOY_MODE=ui for dual-container.
FROM golang:1.26-alpine AS ui-builder
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
COPY backend ./backend
RUN go build -trimpath -ldflags="-s -w" -o /out/registry-ui ./backend/cmd/registry-ui

FROM registry:3 AS registry-bin

FROM alpine:3.24
RUN apk add --no-cache su-exec \
    && adduser -D -H -u 10001 registry-ui \
    && mkdir -p /data/db /data/certs /data/uploads /data/registry /etc/distribution \
    && chown -R registry-ui:registry-ui /data /etc/distribution
COPY --from=ui-builder /out/registry-ui /usr/local/bin/registry-ui
COPY --from=registry-bin /bin/registry /usr/local/bin/registry
COPY --chown=registry-ui:registry-ui deploy/aio/registry-config.yml /etc/distribution/config.yml
COPY deploy/aio/entrypoint.sh /usr/local/bin/registry-ui-entrypoint
RUN chmod 755 /usr/local/bin/registry-ui-entrypoint
EXPOSE 8080 5000
# REGISTRY_URL, REGISTRY_DATA_DIR and REGISTRY_CONFIG are deliberately NOT set
# here. distribution/registry maps any REGISTRY_-prefixed variable onto its own
# config tree (REGISTRY_DATA_DIR becomes storage.data.dir), so an image-wide ENV
# would leak into `registry serve` and `registry garbage-collect` and point GC
# at the wrong storage root. The entrypoint supplies these defaults to the UI
# process only.
ENV SERVER_ADDR=:8080 \
    DATA_DIR=/data \
    SQLITE_PATH=/data/db/registry-ui.db \
    UPLOAD_DIR=/data/uploads \
    CERT_DIR=/data/certs \
    ENABLE_DELETE=true \
    DEPLOY_MODE=aio
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/registry-ui-entrypoint"]
