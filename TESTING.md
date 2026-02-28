# Crispkey Testing

This document describes the containerized testing environment for iterative development of crispkey.

## Overview

The testing setup uses two Podman containers (`alice` and `bob`) in an isolated network to test vault-based encrypted key synchronization.

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
│   │  ~/.config/     │           │  ~/.config/     │        │
│   │  └─ vaults/     │           │  └─ vaults/     │        │
│   │  └─ manifest.enc│           │  └─ manifest.enc│        │
│   └─────────────────┘           └─────────────────┘        │
│                                                              │
│        Encrypted Sync Protocol v2                            │
│        (session key derived from sync password)              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Architecture

### Vault-Based Storage

Keys are now stored in encrypted vaults:

```
~/.config/crispkey/
├── vaults/
│   ├── abc123...def.vault    # Encrypted GPG key
│   └── xyz789...uvw.vault
├── manifest.enc              # Encrypted vault index
├── master_salt               # Salt for master key derivation
├── device_id
└── state.json                # Paired devices, sync history
```

### Security Model

- **Master Password**: Unlocks vaults (PBKDF2 600k iterations)
- **Sync Password**: Authenticates nodes (separate from master)
- **Session Encryption**: All sync traffic encrypted with session keys
- **Per-Vault Keys**: Each vault uses HKDF-derived unique key

### Protocol v2

1. **HELLO**: Exchange device IDs and session IDs (plaintext)
2. **AUTH**: HMAC-based authentication (encrypted)
3. **MANIFEST**: Exchange vault manifests (encrypted)
4. **VAULT_DATA**: Transfer encrypted vaults (no re-encryption needed)

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
# Run full test suite
./scripts/test-all.sh
```

## Test Scripts

| Script | Description |
|--------|-------------|
| `test-setup.sh` | Initialize vault system, generate test GPG keys |
| `test-pair.sh` | Test UDP discovery and device pairing |
| `test-sync.sh` | Test encrypted vault sync between containers |
| `test-all.sh` | Run complete test suite |
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

## Manual Testing

### Initialize Vault System

```bash
# In alice container
podman exec -it -u testuser crispkey-alice crispkey init
# Enter master password: test-master-123
# Enter sync password: test-sync-123

# Unlock vaults
podman exec -it -u testuser crispkey-alice crispkey unlock
# Enter master password: test-master-123
```

### Vault Operations

```bash
# List vaults
podman exec -it -u testuser crispkey-alice crispkey vault list

# Import GPG key to vault
podman exec -it -u testuser crispkey-alice crispkey vault import <fingerprint>

# Export vault to GPG keyring
podman exec -it -u testuser crispkey-alice crispkey vault export <fingerprint>

# Delete a vault
podman exec -it -u testuser crispkey-alice crispkey vault delete <fingerprint>
```

### Sync Vaults

```bash
# Discover peers
podman exec -it -u testuser crispkey-bob crispkey discover

# Pair with alice
podman exec -it -u testuser crispkey-bob crispkey pair <alice_device_id>

# Sync vaults
podman exec -it -u testuser crispkey-bob crispkey unlock
podman exec -it -u testuser crispkey-bob crispkey sync
# Enter remote sync password: test-sync-123
```

### Check Status

```bash
podman exec -it -u testuser crispkey-alice crispkey status
```

## Test Data

### Generated Test Keys

The `test-setup.sh` script generates a test GPG key:

- **Name:** Alice Test
- **Email:** Alice Test@test.local
- **Type:** RSA 2048-bit
- **Passphrase:** None

### Test Credentials

Both containers are initialized with:

- **Master password:** `testmaster123`
- **Sync password:** `testsync123`

## Container Management

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

# Reinitialize
./scripts/test-setup.sh
```

## Troubleshooting

### Vaults locked error

The vault system requires unlocking before operations:

```bash
crispkey unlock
# Enter master password
```

### Sync authentication failed

Ensure you're using the *remote* device's sync password, not your own:

```bash
crispkey sync
# Enter remote device's sync password: (the OTHER node's sync password)
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

### Build failures

Ensure Elixir and dependencies are installed:

```bash
mix local.hex --force
mix local.rebar --force
mix deps.get
```

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
    command: daemon
    restart: unless-stopped
```

2. Create volume directories:

```bash
mkdir -p test-volumes/charlie/config
chmod 755 test-volumes/charlie/config
```

3. Update test scripts as needed.
