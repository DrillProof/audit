# Consumed by goreleaser, which supplies the already-built binary.
#
#   docker run --rm -v ~/.aws:/root/.aws ghcr.io/drillproof/audit scan
#
# The entrypoint includes the `audit` subcommand so the documented invocation
# above works without repeating it.
#
# distroless/static rather than alpine, for a reason that is about build time
# rather than taste: `dockers_v2` builds linux/amd64 and linux/arm64, and on an
# x86 CI runner the arm64 build runs every RUN instruction under QEMU. `apk add`
# emulated is the single slowest thing in the image build. This base ships
# ca-certificates and a uid-65532 `nonroot` user already, so there is nothing
# left to RUN and nothing left to emulate — the arm64 build becomes a file copy.
#
# It is also strictly less to attack: no shell, no package manager, no apk
# database, for a tool whose whole promise is that it only reads.
#
# The `:nonroot` tag is what makes this a drop-in replacement. It carries
# `nonroot:x:65532:65532` in /etc/passwd — the same uid the previous
# `adduser -D -u 65532 drillproof` created — so the USER line below is unchanged
# and the container still runs as the same unprivileged uid. The binary is built
# CGO_ENABLED=0, so a base with no libc is fine.
FROM gcr.io/distroless/static:nonroot

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
