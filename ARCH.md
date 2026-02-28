# Crispkey Architecture

GPG key synchronization across devices using encrypted vaults and peer-to-peer sync.

## Overview

Crispkey enables syncing GPG keys between devices using encrypted vaults:

- **Vault Storage** - Keys stored in individually encrypted vault files
- **UDP Multicast** - Peer discovery on local network
- **Encrypted Sync** - Session-based encrypted communication
- **Separate Passwords** - Master password for vaults, sync password for authentication

## Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                         Security Layers                          │
├─────────────────────────────────────────────────────────────────┤
│  Master Password → PBKDF2(600k iter) → Master Key               │
│                                              │                   │
│                         ┌────────────────────┴───────────────┐  │
│                         ▼                                    ▼  │
│              Vault Key (per vault)              Manifest Key    │
│              HKDF(master, fingerprint)          HKDF(master)    │
│                         │                                       │
│                         ▼                                       │
│              AES-256-GCM Encrypted Vault                        │
├─────────────────────────────────────────────────────────────────┤
│  Sync Password → HKDF(session_id) → Session Key                 │
│                         │                                       │
│                         ▼                                       │
│              AES-256-GCM Encrypted Transport                    │
└─────────────────────────────────────────────────────────────────┘
```

**Key Insight**: Vaults are encrypted independently of sync. When syncing, encrypted vaults are transferred as-is without re-encryption.

## Repository Structure

```
crispkey/
├── lib/crispkey/
│   ├── application.ex           # OTP application supervisor
│   ├── cli.ex                   # CLI command dispatcher
│   ├── crispkey.ex              # Core module (device_id, config access)
│   ├── crypto/
│   │   └── key_wrapper.ex       # Legacy key wrapping (for backward compat)
│   ├── gpg/
│   │   ├── interface.ex         # GPG CLI wrapper
│   │   └── types.ex             # Key, UID, Subkey structs
│   ├── merge/
│   │   └── engine.ex            # Key merge conflict detection
│   ├── store/
│   │   ├── local_state.ex       # Persistent state
│   │   ├── peers.ex             # Discovered peers cache
│   │   └── types.ex             # State, Peer structs
│   ├── vault/
│   │   ├── crypto.ex            # HKDF, AES-GCM for vaults
│   │   ├── manager.ex           # Vault CRUD, master key caching
│   │   ├── manifest.ex          # Vault index management
│   │   └── types.ex             # Vault, Manifest, Session structs
│   └── sync/
│       ├── connection.ex        # Client-side encrypted sync
│       ├── daemon.ex            # Background discovery listener
│       ├── discovery.ex         # UDP multicast discovery
│       ├── listener.ex          # TCP sync listener
│       ├── message.ex           # Wire protocol message structs
│       ├── peer.ex              # Server-side encrypted sync
│       ├── protocol.ex          # v2 protocol with encryption
│       └── session.ex           # Session key derivation, encryption
├── config/config.exs
├── mix.exs
└── README.md
```

## Storage Layout

```
~/.config/crispkey/
├── vaults/
│   ├── abc123def456.vault    # Encrypted GPG key bundle
│   └── xyz789uvw012.vault
├── manifest.enc              # Encrypted vault index
├── master_salt               # Salt for PBKDF2
├── device_id                 # 16 hex chars
├── state.json                # Paired devices, sync history
└── discovered_peers.json     # Transient peer cache
```

## Core Components

### Vault System

#### Vault.Crypto (`lib/crispkey/vault/crypto.ex`)

Cryptographic operations for vault encryption:

```elixir
# Master key derivation
master_key = PBKDF2(password, salt, 600k iterations, SHA256)

# Per-vault key derivation using HKDF
vault_key = HKDF-SHA256(master_key, fingerprint, 32 bytes)

# Vault encryption
encrypted = AES-256-GCM(plaintext, vault_key, random_nonce)
```

#### Vault.Manager (`lib/crispkey/vault/manager.ex`)

GenServer managing vault lifecycle:
- Caches master key in memory when unlocked
- Creates, reads, updates, deletes vaults
- Syncs manifest on changes
- Handles raw vault transfer for sync

#### Vault.Manifest (`lib/crispkey/vault/manifest.ex`)

Manifest management:
- Tracks vault fingerprints, sizes, hashes
- Enables incremental sync (only transfer changed vaults)
- Supports diff and merge operations

### Sync Protocol v2

#### Session (`lib/crispkey/sync/session.ex`)

Encrypted session management:
- Session key derived from sync password + session ID
- Counter-based nonces for message encryption
- HMAC-based authentication tokens

#### Protocol (`lib/crispkey/sync/protocol.ex`)

Wire protocol v2:
- HELLO: Exchange device_id, session_id (plaintext)
- AUTH_TOKEN: HMAC-based auth (encrypted)
- MANIFEST_REQUEST/MANIFEST: Exchange vault index (encrypted)
- VAULT_REQUEST/VAULT_DATA: Transfer encrypted vaults (encrypted wrapper)

#### Connection (`lib/crispkey/sync/connection.ex`)

Client-side sync:
1. Connect and handshake with session ID
2. Authenticate with HMAC token
3. Exchange manifests
4. Request and receive needed vaults

#### Peer (`lib/crispkey/sync/peer.ex`)

Server-side sync (GenServer):
- Handles incoming connections
- Authenticates clients
- Serves manifest and vault data

### CLI Commands

```bash
# Vault management
crispkey init              # Initialize vault system
crispkey unlock            # Unlock vaults with master password
crispkey lock              # Clear master key from memory
crispkey vault list        # List vaults
crispkey vault import <fp> # Import GPG key to vault
crispkey vault export <fp> # Export vault to GPG keyring
crispkey vault delete <fp> # Delete a vault

# Sync
crispkey discover [sec]    # Find devices on network
crispkey pair <id|host>    # Pair with a device
crispkey sync [device]     # Sync vaults with device

# Info
crispkey status            # Show status
crispkey keys              # List GPG keys in keyring
crispkey devices           # List paired devices
```

## Sync Flow

```
Client (Bob)                              Server (Alice)
    │                                          │
    │──── HELLO(device_id, session_id) ──────►│
    │◄─── HELLO(device_id, session_id) ───────│
    │                                          │
    │  [Derive session_key from sync_password] │
    │                                          │
    │──── AUTH_TOKEN(hmac) [encrypted] ──────►│
    │◄─── AUTH_OK [encrypted] ────────────────│
    │                                          │
    │──── MANIFEST_REQUEST [encrypted] ──────►│
    │◄─── MANIFEST(data) [encrypted] ─────────│
    │                                          │
    │  [Compare manifests, find needed vaults] │
    │                                          │
    │──── VAULT_REQUEST(fps) [encrypted] ────►│
    │◄─── VAULT_DATA(fp, encrypted_blob) ─────│
    │◄─── VAULT_DATA(fp, encrypted_blob) ─────│
    │                                          │
    │  [Store vaults, no decryption needed]    │
    │                                          │
    │──── GOODBYE [encrypted] ───────────────►│
```

## Vault Format

Each vault file contains:

```
┌────────────────────────────────────────┐
│ 32 bytes: salt (for vault key deriv)   │
│ 12 bytes: nonce (AES-GCM)              │
│ 16 bytes: auth tag                     │
│ N bytes: ciphertext                    │
└────────────────────────────────────────┘

Ciphertext (decrypted):
{
  "fingerprint": "abc123...",
  "public": "-----BEGIN PGP PUBLIC KEY-----...",
  "secret": "-----BEGIN PGP PRIVATE KEY-----...",
  "trust": "# ownertrust database",
  "metadata": {...}
}
```

## Security Properties

| Threat | Protection |
|--------|------------|
| Vault file stolen | Encrypted with master key (PBKDF2 600k iter) |
| Sync traffic intercepted | Encrypted with session key |
| Sync password compromised | Can sync, but can't read vaults |
| Master password compromised | Can read vaults, but can't impersonate for sync |
| One vault compromised | Others use different HKDF-derived keys |
| Replay attack | Counter-based nonces, session IDs |

## Configuration

```elixir
# config/config.exs
config :crispkey,
  gpg_homedir: "~/.gnupg",
  data_dir: "~/.config/crispkey",
  sync_port: 4829,      # TCP sync
  discovery_port: 4830  # UDP multicast
```

## Dependencies

- `jason` - JSON encoding/decoding
- `ranch` - TCP acceptor pool
- `norm` - Data validation
- Built-in Erlang `:crypto` - PBKDF2, AES-GCM, HKDF

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4829 | TCP | Sync protocol (encrypted) |
| 4830 | UDP | Discovery multicast |

## Migration from v1

If upgrading from the legacy format:

1. Export keys from old GPG keyring
2. Run `crispkey init` to set up vault system
3. Run `crispkey unlock`
4. Run `crispkey vault import <fingerprint>` for each key

## Future Work

- Vault sharing with per-user access
- Relay server for remote sync
- Conflict resolution UI
- Hardware key support (YubiKey)
