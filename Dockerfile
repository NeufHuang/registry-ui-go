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
RUN adduser -D -H -u 10001 registry-ui \
    && mkdir -p /data/db /data/certs /data/uploads /data/registry /etc/distribution \
    && chown -R registry-ui:registry-ui /data /etc/distribution
COPY --from=ui-builder /out/registry-ui /usr/local/bin/registry-ui
COPY --from=registry-bin /bin/registry /usr/local/bin/registry
COPY --chown=registry-ui:registry-ui deploy/aio/registry-config.yml /etc/distribution/config.yml
COPY deploy/aio/entrypoint.sh /usr/local/bin/registry-ui-entrypoint
RUN chmod 755 /usr/local/bin/registry-ui-entrypoint
USER registry-ui
EXPOSE 8080 5000
ENV SERVER_ADDR=:8080 \
    REGISTRY_URL=http://127.0.0.1:5000 \
    DATA_DIR=/data \
    SQLITE_PATH=/data/db/registry-ui.db \
    UPLOAD_DIR=/data/uploads \
    CERT_DIR=/data/certs \
    REGISTRY_DATA_DIR=/data/registry \
    ENABLE_DELETE=true \
    REGISTRY_CONFIG=/etc/distribution/config.yml \
    DEPLOY_MODE=aio
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/registry-ui-entrypoint"]
