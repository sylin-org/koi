# ADR-018 Tier 3 — thin runtime image for the cross-host certmesh integration test.
#
# It carries ONLY a prebuilt static (musl) `koi` binary; the build is done on the host
# (or CI runner) with `cross` — the same toolchain the release workflow uses — and staged
# into this directory by scripts/cross-host-certmesh.sh. The tiny build context (this dir,
# not the repo) keeps the image build fast and avoids a compile-in-Docker.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY koi /usr/local/bin/koi
RUN chmod +x /usr/local/bin/koi

# No OS keychain in a container — seal the CA with the machine-bound vault instead.
ENV KOI_NO_CREDENTIAL_STORE=1
ENV KOI_LOG=warn
# Reachable from the OTHER container (the binary daemon binds loopback by default; the
# breadcrumb still advertises loopback for the in-container client). Mutations remain
# DAT-token gated; the compose bridge is the only exposure.
ENV KOI_HTTP_BIND=0.0.0.0

EXPOSE 5641 5642

# A lean certmesh + HTTP daemon (the mTLS listener comes up once a CA exists). Everything
# else off so the container needs no privileged/multicast ports.
ENTRYPOINT ["koi"]
CMD ["--daemon", \
     "--no-mdns", "--no-dns", "--no-health", "--no-proxy", "--no-udp", \
     "--no-runtime", "--no-acme", "--no-mcp-http", "--no-ipc"]
