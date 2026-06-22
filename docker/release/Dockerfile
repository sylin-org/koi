# Published Koi container image: ghcr.io/sylin-org/koi
#
# This image carries the prebuilt static (musl) `koi` binary from the GitHub
# Release — the exact same artifact you would download by hand. The release
# workflow cross-compiles both arches, stages them next to this Dockerfile as
# `koi-amd64` / `koi-arm64`, and `docker buildx` assembles a multi-arch manifest
# (linux/amd64 + linux/arm64). Nothing is compiled in Docker.
#
# Build locally (after staging a binary named koi-<arch> beside this file):
#   docker build -t koi docker/release
FROM alpine:3.20

# ca-certificates: outbound TLS (ACME, upstream DNS). wget (busybox) powers the
# HEALTHCHECK below.
RUN apk add --no-cache ca-certificates

# `docker buildx` sets TARGETARCH to amd64 / arm64 per platform; pick the matching
# prebuilt binary that CI staged into the build context.
ARG TARGETARCH
COPY koi-${TARGETARCH} /usr/local/bin/koi
RUN chmod +x /usr/local/bin/koi

# No OS keychain inside a container — seal the CA with the machine-bound vault.
ENV KOI_NO_CREDENTIAL_STORE=1
# A loopback bind is invisible to other containers; bind the container's
# interfaces so the compose/bridge network can reach the daemon. Mutations stay
# DAT-token gated regardless of bind address (see SECURITY.md).
ENV KOI_HTTP_BIND=0.0.0.0
ENV KOI_LOG=info

# HTTP API (5641) and the inter-node mTLS listener (5642). The ACME TLS listener
# (5643) binds only once the CA is initialized and DNS is active, so it is not
# exposed here by default; add `EXPOSE 5643` (and a port mapping) if you use it.
EXPOSE 5641 5642

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:5641/healthz >/dev/null 2>&1 || exit 1

# OCI provenance. The version/source/revision labels are layered on at build
# time by docker/metadata-action; these are the static descriptors.
LABEL org.opencontainers.image.title="koi" \
      org.opencontainers.image.description="Zero-config LAN substrate: mDNS, private CA, DNS, health, proxy, UDP bridging." \
      org.opencontainers.image.source="https://github.com/sylin-org/koi" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENTRYPOINT ["koi"]
# Run the full daemon. Override to trim capabilities, e.g.:
#   docker run ghcr.io/sylin-org/koi --daemon --no-proxy --no-udp
CMD ["--daemon"]
