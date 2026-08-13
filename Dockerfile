# Consumed by goreleaser, which supplies the already-built binary.
#
#   docker run --rm -v ~/.aws:/root/.aws ghcr.io/drillproof/audit scan
#
# The entrypoint includes the `audit` subcommand so the documented invocation
# above works without repeating it.
FROM alpine:3.21

# ca-certificates is required to talk to AWS at all. No other packages: a tool
# whose whole promise is that it only reads should have as little in the image
# as possible.
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 65532 drillproof

# goreleaser's `dockers_v2` builds one platform at a time and lays the context
# out as <os>/<arch>/<binary> — the binary is NOT at the context root. buildx
# populates TARGETPLATFORM as exactly "linux/amd64" or "linux/arm64", which is
# the directory name, so this resolves for both without a per-arch Dockerfile.
#
# `COPY drillproof /drillproof` fails here with a misleading
# `failed to compute cache key: "/drillproof": not found`, which reads like the
# binary was never built rather than like it is one directory down.
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/drillproof /drillproof

# Runs unprivileged. The audit needs no root, no capabilities, no writable
# filesystem.
USER 65532:65532

ENTRYPOINT ["/drillproof", "audit"]
CMD ["scan"]
