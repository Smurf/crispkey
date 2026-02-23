# Crispkey Test Container
# Multi-stage build: compile with Elixir, run on Alpine

# Stage 1: Build the escript
FROM docker.io/elixir:1.15-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git

# Copy mix.exs and fetch dependencies first (layer caching)
COPY mix.exs mix.lock ./
RUN mix local.hex --force && \
    mix local.rebar --force && \
    mix deps.get --only prod

# Copy source and build
COPY lib ./lib
COPY config ./config
RUN MIX_ENV=prod mix escript.build

# Stage 2: Minimal runtime
FROM docker.io/alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    erlang \
    gnupg \
    bash \
    expect \
    inotify-tools \
    curl \
    jq

# Create non-root user for testing
RUN adduser -D -h /home/testuser testuser

# Copy escript from builder
COPY --from=builder /build/crispkey /usr/local/bin/crispkey
RUN chmod +x /usr/local/bin/crispkey

# Set up working directory
WORKDIR /home/testuser

# Default environment
ENV GNUPGHOME=/home/testuser/.gnupg
ENV CRISPKEY_DATA_DIR=/home/testuser/.config/crispkey

# Entry point: can be overridden for testing
ENTRYPOINT ["crispkey"]
CMD ["daemon"]
