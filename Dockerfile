# syntax=docker/dockerfile:1
#
# One image, one process: the web UI is built, embedded into a static Go
# binary, and that binary is the only thing in the final image.
#
# Base images are pinned by digest (the tag is kept for humans). Dependabot
# proposes updates, so they are reviewed rather than floating.

# ---- 1. build the web UI ----------------------------------------------------
FROM node:26-alpine@sha256:40cd011b55415bc894e45b02fdd5a5dfde056921b7d23a64c74f80497af48797 AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci
COPY web/ ./
RUN npm run check && npm test && npm run build

# ---- 2. build the Go binary, with the UI embedded -----------------------------
FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
COPY --from=ui /src/web/dist ./web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/pki-dash ./cmd/pki-dash
# The data directory is created here so it belongs to the unprivileged user.
RUN mkdir /out/data && chown 65532:65532 /out/data && chmod 700 /out/data

# ---- 3. the runtime image: no shell, no package manager, not root ---------------
# Two ways to fill it, sharing everything else:
#   - the default (the last stage, so a plain `docker build .` and `make docker`):
#     the binary built above;
#   - "release": the binary GoReleaser already built (docker build --target
#     release), laid out as <os>/<arch>/pki-dash in the build context.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087 AS base
ARG VERSION=dev
LABEL org.opencontainers.image.title="pki-dash" \
      org.opencontainers.image.description="Web dashboard for managing an internal PKI, built on cfssl" \
      org.opencontainers.image.source="https://github.com/marcioamatte/pki-dash" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
USER 65532:65532
ENV PKI_DASH_DATA_DIR=/data \
    PKI_DASH_LISTEN=0.0.0.0:8443
EXPOSE 8443 8080
# No default command on purpose: the server will not start until the operator
# chooses how it is served (-tls-cert/-tls-key, -tls-self-signed or -insecure-http).
ENTRYPOINT ["/pki-dash"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/pki-dash", "healthcheck"]

FROM base AS release
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/pki-dash /pki-dash
# An empty data directory owned by the unprivileged user, so a new volume is writable.
COPY --chown=65532:65532 --chmod=0700 packaging/docker/data /data
VOLUME /data

FROM base
COPY --from=build /out/pki-dash /pki-dash
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
VOLUME /data
