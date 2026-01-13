# syntax=docker/dockerfile:1.4

# Sentinel Bot Management Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-agent-bot-management /sentinel-agent-bot-management

LABEL org.opencontainers.image.title="Sentinel Bot Management Agent" \
      org.opencontainers.image.description="Sentinel Bot Management Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-bot-management"

ENV RUST_LOG=info,sentinel_agent_bot_management=debug \
    SOCKET_PATH=/var/run/sentinel/bot-management.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-agent-bot-management"]
