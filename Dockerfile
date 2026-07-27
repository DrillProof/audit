# Consumed by goreleaser, which supplies the already-built binary.
#
#   docker run --rm -v ~/.aws:/root/.aws drillproof/audit scan
#
# The entrypoint includes the `audit` subcommand so the documented invocation
# above works without repeating it.
FROM alpine:3.21

# ca-certificates is required to talk to AWS at all. No other packages: a tool
# whose whole promise is that it only reads should have as little in the image
# as possible.
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 65532 drillproof

COPY drillproof /drillproof

# Runs unprivileged. The audit needs no root, no capabilities, no writable
# filesystem.
USER 65532:65532

ENTRYPOINT ["/drillproof", "audit"]
CMD ["scan"]
