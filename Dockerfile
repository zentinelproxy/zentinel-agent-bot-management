# syntax=docker/dockerfile:1.4

# Zentinel Bot Management Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-bot-management-agent /zentinel-bot-management-agent

LABEL org.opencontainers.image.title="Zentinel Bot Management Agent" \
      org.opencontainers.image.description="Zentinel Bot Management Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-bot-management"

ENV RUST_LOG=info,zentinel_agent_bot_management=debug \
    SOCKET_PATH=/var/run/zentinel/bot-management.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-bot-management-agent"]
