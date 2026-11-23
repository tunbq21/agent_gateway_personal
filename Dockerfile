# syntax=docker/dockerfile:1.11
ARG BUILDER=base

FROM docker.io/library/node:24.22.1-bookworm AS node

WORKDIR /app

COPY ui .
COPY schema /schema

RUN corepack enable

RUN --mount=type=cache,id=agentgateway-ui-pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --store-dir=/pnpm/store

RUN pnpm build

FROM docker.io/library/rust:1.99.0-trixie AS musl-builder

ARG TARGETARCH

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache && \
    apt-get update && apt-get install -y --no-install-recommends \
    make musl-tools

RUN <<EOF
mkdir /build
if [ "$TARGETARCH" = "arm64" ]; then
  rustup target add aarch64-unknown-linux-musl;
  echo aarch64-unknown-linux-musl > /build/target
else
  rustup target add x86_64-unknown-linux-musl;
  echo x86_64-unknown-linux-musl > /build/target
fi
EOF

FROM docker.io/library/rust:1.99.0-trixie AS base-builder

ARG TARGETARCH

RUN <<EOF
mkdir /build
if [ "$TARGETARCH" = "arm64" ]; then
  echo aarch64-unknown-linux-gnu > /build/target
else
  echo x86_64-unknown-linux-gnu > /build/target
fi
echo "Building $(cat /build/target)"
EOF

FROM ${BUILDER}-builder AS builder
ARG TARGETARCH
ARG PROFILE=release
ARG VERSION=Personal-1.0.0
ARG GIT_REVISION=personal
ARG CARGO_FEATURES=agentgateway-app/ui
ARG CARGO_NO_DEFAULT_FEATURES=false

WORKDIR /app

COPY Makefile Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY tools ./tools
RUN chmod +x ./tools/*.sh
COPY catalog ./catalog
COPY --from=node /app/dist ./ui/dist

RUN \
    --mount=type=cache,id=cargo,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    cargo fetch --locked
RUN --mount=type=cache,target=/app/target \
    --mount=type=cache,id=cargo,target=/usr/local/cargo/registry  \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    <<EOF
export VERSION="${VERSION}"
export GIT_REVISION="${GIT_REVISION}"
# Build jemalloc for 64KB pages on arm64 so the image runs on hosts with any page
# size <= 64KB (4KB/16KB/64KB).
if [ "${TARGETARCH}" = "arm64" ]; then
  export JEMALLOC_SYS_WITH_LG_PAGE=16
fi
if [ "${CARGO_NO_DEFAULT_FEATURES}" = "true" ]; then
  cargo build --no-default-features --features "${CARGO_FEATURES}" --target "$(cat /build/target)" --profile ${PROFILE} || exit 1
else
  cargo build --features "${CARGO_FEATURES}" --target "$(cat /build/target)" --profile ${PROFILE} || exit 1
fi
mkdir /out
mv /app/target/$(cat /build/target)/${PROFILE}/agentgateway /out
/out/agentgateway --version || exit 1
# Fail if version is not set
if /out/agentgateway --version | grep -q '"version": "unknown"'; then
  exit 1
fi
EOF

FROM docker.io/library/python:3.12-slim-trixie AS runner

ENV AGENTGATEWAY_ENV=container

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir "starlette>=0.41,<1" "uvicorn>=0.32,<1" "httpx>=0.27,<1" "pyyaml>=6,<7" && \
    groupadd --system appuser && useradd --system --gid appuser --home-dir /app appuser

WORKDIR /app

COPY --from=builder /out/agentgateway /app/agentgateway
COPY --from=node /app/dist /app/ui/dist
COPY start_local_gateway.py /app/start_local_gateway.py
COPY personal_ui_proxy.py /app/personal_ui_proxy.py
COPY config.personal.yaml /config/config.yaml
RUN chown -R appuser:appuser /app /config

USER appuser

EXPOSE 3000 15005 15020 15021

LABEL org.opencontainers.image.source=https://github.com/tunbq21/agent_gateway_personal
LABEL org.opencontainers.image.description="TunAI Personal AI & MCP Gateway"

ENTRYPOINT ["python", "/app/personal_ui_proxy.py"]
