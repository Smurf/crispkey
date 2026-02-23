# Crispkey Testing

This document describes the containerized testing environment for iterative development of crispkey.

## Overview

The testing setup uses two Podman containers (`alice` and `bob`) in an isolated network to test pairing and syncing functionality without affecting your LAN or production GPG keys.

```
┌─────────────────────────────────────────────────────────────┐
│                    Podman Network                            │
│                    (crispkey-test)                           │
│                                                              │
│   ┌─────────────────┐           ┌─────────────────┐        │
│   │   Container A   │           │   Container B   │        │
│   │   (alice)       │           │   (bob)         │        │
│   │                 │           │                 │        │
│   │  UDP 4830 ◄─────┼───────────┼─────► UDP 4830  │        │
│   │  TCP 4829 ◄─────┼───────────┼─────► TCP 4829  │        │
│   │                 │           │                 │        │
│   │  ~/.gnupg       │           │  ~/.gnupg       │        │
│   │  ~/.config/     │           │  ~/.config/     │        │
│   └─────────────────┘           └─────────────────┘        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- **Podman** - Container runtime
- **podman-compose** - Compose support for Podman
- **Elixir** - For building the escript
- **inotify-tools** or **fswatch** - For file watching (iterative mode)

### Installing Prerequisites

**Fedora/RHEL:**
```bash
sudo dnf install podman podman-compose inotify-tools
```

**Ubuntu/Debian:**
```bash
sudo apt install podman podman-compose inotify-tools
```

**macOS:**
```bash
brew install podman podman-compose fswatch
```

## Quick Start

```bash
# Build and start containers
podman-compose -f docker-compose.podman.yml up -d --build

# Run full test suite
./scripts/test-all.sh
```

## Test Scripts

| Script | Description |
|--------|-------------|
| `test-setup.sh` | Initialize crispkey, generate test GPG keys in alice |
| `test-pair.sh` | Test UDP discovery and device pairing |
| `test-sync.sh` | Test key synchronization between containers |
| `test-all.sh` | Run complete test suite (setup → pair → sync) |
| `iterative-test.sh` | Watch for code changes, rebuild, and retest |

## Iterative Development

For continuous testing during development:

```bash
./scripts/iterative-test.sh
```

This will:
1. Build the crispkey escript
2. Deploy to both containers
3. Run all tests
4. Watch `lib/` and `config/` for changes
5. On change: rebuild → redeploy → retest

### Workflow

```
[ Watch lib/**/*.ex ]
        │
        ▼ (on change)
[ mix escript.build ]
        │
        ▼
[ podman cp to containers ]
        │
        ▼
[ podman restart alice bob ]
        │
        ▼
[ test-all.sh ]
        │
        ▼
[ Report: ✓ PASS / ✗ FAIL ]
        │
        ▼
[ Wait for next change ]
```

## Manual Testing

### Start Containers

```bash
podman-compose -f docker-compose.podman.yml up -d --build
```

### Check Container Status

```bash
podman ps
podman logs crispkey-alice
podman logs crispkey-bob
```

### Run Commands in Containers

```bash
# In alice
podman exec -it -u testuser crispkey-alice crispkey status
podman exec -it -u testuser crispkey-alice crispkey discover

# In bob
podman exec -it -u testuser crispkey-bob crispkey status
```

### Rebuild and Redeploy

```bash
mix escript.build
podman cp crispkey crispkey-alice:/usr/local/bin/crispkey
podman cp crispkey crispkey-bob:/usr/local/bin/crispkey
podman restart crispkey-alice crispkey-bob
```

### Stop Containers

```bash
podman-compose -f docker-compose.podman.yml down
```

### Clean State

```bash
# Remove test volumes
rm -rf test-volumes/alice/* test-volumes/bob/*

# Or just rerun test-setup.sh
./scripts/test-setup.sh
```

## Test Data

### Generated Test Keys

The `test-setup.sh` script generates a test GPG key in the `alice` container:

- **Name:** Alice Test
- **Email:** Alice Test@test.local
- **Type:** RSA 2048-bit
- **Passphrase:** None (for easier testing)

### Sync Credentials

Both containers are initialized with:

- **Master passphrase:** `test-master-passphrase-456`
- **Sync password:** `test-sync-password-123`

## Architecture

### Containerfile

Multi-stage build:

1. **Builder stage** (`elixir:1.15-alpine`): Compiles the escript
2. **Runtime stage** (`alpine:3.19`): Minimal image with GPG and runtime deps

### Network Configuration

- **Network:** `crispkey-test` (isolated bridge)
- **Multicast:** Enabled for UDP discovery
- **Ports:** 4829/tcp (sync), 4830/udp (discovery) - internal only

### Volume Mounts

```
test-volumes/alice/config → /home/testuser/.config/crispkey
test-volumes/alice/gnupg → /home/testuser/.gnupg
test-volumes/bob/config → /home/testuser/.config/crispkey
test-volumes/bob/gnupg → /home/testuser/.gnupg
```

## Adding More Containers

To add a third container for N-way testing:

1. Add to `docker-compose.podman.yml`:

```yaml
  charlie:
    build:
      context: .
      dockerfile: Containerfile
    container_name: crispkey-charlie
    hostname: charlie
    networks:
      - crispkey-test
    volumes:
      - ./test-volumes/charlie/config:/home/testuser/.config/crispkey
      - ./test-volumes/charlie/gnupg:/home/testuser/.gnupg
    command: daemon
    restart: unless-stopped
```

2. Create volume directories:

```bash
mkdir -p test-volumes/charlie/config test-volumes/charlie/gnupg
chmod 700 test-volumes/charlie/gnupg
```

3. Update test scripts as needed.

## Troubleshooting

### Containers won't start

```bash
# Check logs
podman logs crispkey-alice

# Rebuild
podman-compose -f docker-compose.podman.yml up -d --build
```

### Discovery not working

1. Ensure both daemons are running:
   ```bash
   podman exec -u testuser crispkey-alice pgrep -f crispkey
   podman exec -u testuser crispkey-bob pgrep -f crispkey
   ```

2. Check network connectivity:
   ```bash
   podman exec crispkey-alice ping -c 1 bob
   ```

### Permission errors

The containers run as `testuser`. Ensure volume directories are accessible:

```bash
# Fix permissions
chmod -R 755 test-volumes/
chmod 700 test-volumes/*/gnupg
```

### Build failures

Ensure Elixir and dependencies are installed:

```bash
mix local.hex --force
mix local.rebar --force
mix deps.get
```

### Port conflicts

If ports 4829/4830 are in use on your host, note that these are only used internally in the container network and should not conflict with host ports.

## CI Integration

For CI pipelines:

```bash
#!/bin/bash
set -e

# Start containers
podman-compose -f docker-compose.podman.yml up -d --build

# Wait for containers
sleep 5

# Run tests
./scripts/test-all.sh
```

Exit code will be 0 on success, non-zero on failure.
