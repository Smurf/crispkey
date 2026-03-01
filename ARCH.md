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
│  Sync Password → SHA256 hash → stored in state.json            │
│                                              │                   │
│                         ▼                                       │
│              Session Key = HKDF(password_hash, session_id)      │
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
│   ├── crispkey.ex              # Core module (device_id, config access)
│   ├── cli.ex                   # CLI command dispatcher
│   ├── gpg/
│   │   ├── interface.ex         # GPG CLI wrapper
│   │   └── types.ex             # Key, UID, Subkey structs
│   ├── merge/
│   │   └── engine.ex            # Key merge conflict detection
│   ├── store/
│   │   ├── local_state.ex       # Persistent state GenServer
│   │   ├── peers.ex             # Discovered peers cache (file-based)
│   │   └── types.ex             # State, Peer structs
│   ├── vault/
│   │   ├── crypto.ex            # HKDF, AES-GCM for vaults and sessions
│   │   ├── manager.ex           # Vault CRUD, master key caching (GenServer)
│   │   ├── manifest.ex          # Vault index management (ManifestModule)
│   │   └── types.ex             # Vault, Manifest, VaultEntry, Session structs
│   └── sync/
│       ├── connection.ex        # Client-side encrypted sync
│       ├── daemon.ex            # Background discovery listener (GenServer)
│       ├── discovery.ex         # UDP multicast discovery
│       ├── listener.ex          # TCP sync listener (GenServer)
│       ├── message.ex           # Wire protocol message structs
│       ├── peer.ex              # Server-side encrypted sync (GenServer)
│       ├── protocol.ex          # v2 protocol with encryption
│       └── session.ex           # Session key derivation, encryption
├── config/
│   ├── config.exs               # Application configuration
│   └── runtime.exs              # Runtime configuration
├── mix.exs
└── ARCH.md
```

## OTP Supervision Tree

```
Crispkey.Supervisor (one_for_one)
├── Crispkey.Store.LocalState (GenServer)
└── Crispkey.Vault.Manager (GenServer)

When daemon mode is active (started via CLI):
├── Crispkey.Sync.Listener (GenServer, not supervised)
└── Crispkey.Sync.Daemon (GenServer, not supervised)
```

## Storage Layout

```
~/.config/crispkey/
├── vaults/
│   ├── abc123def456.vault    # Encrypted GPG key bundle
│   └── xyz789uvw012.vault
├── manifest.enc              # Encrypted vault index
├── master_salt               # Salt for PBKDF2 (32 bytes)
├── device_id                 # 16 hex chars
├── state.json                # Paired devices, sync history, sync password hash
└── discovered_peers.json     # Transient peer cache
```

## Core Components

### Vault System

#### Vault.Crypto (`lib/crispkey/vault/crypto.ex`)

Cryptographic operations for vault and session encryption:

```elixir
# Master key derivation
master_key = PBKDF2(password, salt, 600k iterations, SHA256)

# Per-vault key derivation using HKDF
vault_key = HKDF-SHA256(master_key, fingerprint, 32 bytes)

# Manifest key derivation
manifest_key = HKDF-SHA256(master_key, "manifest", 32 bytes)

# Vault encryption
encrypted = AES-256-GCM(plaintext, vault_key, random_nonce)

# Session key derivation (sync)
session_key = HKDF-SHA256(password_hash, session_id, 32 bytes)
```

#### Vault.Manager (`lib/crispkey/vault/manager.ex`)

GenServer managing vault lifecycle:
- Caches master key in memory when unlocked
- Creates, reads, updates, deletes vaults
- Syncs manifest on changes
- Handles raw vault transfer for sync
- Auto-unlock from `CRISPKEY_MASTER_PASSWORD` env var

#### Vault.ManifestModule (`lib/crispkey/vault/manifest.ex`)

Manifest management (functional module, not a GenServer):
- Tracks vault fingerprints, sizes, hashes
- Enables incremental sync (only transfer changed vaults)
- Supports diff and merge operations

### Sync Protocol v2

#### Types.Session (`lib/crispkey/vault/types.ex`)

Session state struct with encrypted communication:
- `session_id`: 16 random bytes
- `session_key`: Derived from sync password hash + session ID
- `nonce_counter`: Counter for nonce generation
- `peer_id`: Connected peer's device ID

#### Session (`lib/crispkey/sync/session.ex`)

Encrypted session management:
- Session key derived from sync password hash + session ID
- Counter-based nonces for message encryption
- HMAC-based authentication tokens

#### Protocol (`lib/crispkey/sync/protocol.ex`)

Wire protocol v2:
- HELLO: Exchange device_id, session_id (plaintext)
- AUTH_TOKEN: HMAC-based auth (encrypted)
- AUTH_OK/AUTH_FAIL: Authentication response (encrypted)
- MANIFEST_REQUEST/MANIFEST: Exchange vault index (encrypted)
- VAULT_REQUEST/VAULT_DATA: Transfer encrypted vaults (encrypted wrapper)
- ACK: End of vault transfer

#### Connection (`lib/crispkey/sync/connection.ex`)

Client-side sync:
1. Connect and handshake with session ID
2. Authenticate with HMAC token
3. Exchange manifests
4. Request and receive needed vaults

#### Peer (`lib/crispkey/sync/peer.ex`)

Server-side sync (GenServer):
- Handles incoming connections
- Authenticates clients using stored sync password hash
- Serves manifest and vault data

#### Message (`lib/crispkey/sync/message.ex`)

Typed message structs for wire protocol:
- Hello, Auth, AuthOk, AuthFail
- Inventory, Request, KeyData, TrustData
- Ack, Goodbye

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
crispkey status            # Show sync status
crispkey keys              # List GPG keys in keyring
crispkey devices           # List paired devices
crispkey daemon            # Start background sync daemon
crispkey discover [sec]    # Find devices on network
crispkey pair <id|host>    # Pair with a device
crispkey sync [device]     # Sync vaults with device(s)
```

### Environment Variables

- `CRISPKEY_DATA_DIR`: Override data directory
- `GNUPGHOME`: Override GPG home directory
- `CRISPKEY_MASTER_PASSWORD`: Auto-unlock vaults on startup

## Sync Flow

```
Client (Bob)                              Server (Alice)
    │                                          │
    │──── HELLO(device_id, session_id) ──────►│
    │◄─── HELLO(device_id, session_id) ───────│
    │                                          │
    │  [Both derive session_key from           │
    │   sync_password_hash + session_id]       │
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
    │◄─── ACK [encrypted] ────────────────────│
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

## Wire Protocol Format

All messages use a 4-byte length prefix:

```
┌────────────────────────────────────────┐
│ 4 bytes: message length (big-endian)   │
│ N bytes: JSON message payload          │
└────────────────────────────────────────┘
```

Encrypted messages (after HELLO):

```
┌────────────────────────────────────────┐
│ 4 bytes: payload length                │
│ 12 bytes: nonce                        │
│ 16 bytes: auth tag                     │
│ N bytes: ciphertext (JSON message)     │
└────────────────────────────────────────┘
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
| Atom table exhaustion | Explicit atom conversion in message decoding |

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
- `ranch` - TCP acceptor pool (dependency, not currently used directly)
- `norm` - Data validation
- `dialyxir` - Static analysis (dev/test)
- `credo` - Code style (dev/test)
- `proper` - Property-based testing (dev/test)
- Built-in Erlang `:crypto` - PBKDF2, AES-GCM, HKDF

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4829 | TCP | Sync protocol (encrypted) |
| 4830 | UDP | Discovery multicast |

## GPG Integration

The GPG.Interface module wraps the GPG CLI:
- Uses `--with-colons` machine-readable output
- Parses public/secret keys, UIDs, and subkeys
- Supports import/export of keys and trust database
- Respects `GNUPGHOME` environment variable

## Merge Engine

The Merge.Engine module handles conflict detection:
- UID conflicts (both sides added new UIDs)
- Subkey conflicts (both sides added new subkeys)
- Expiry conflicts (different expiry dates)
- Returns `{:conflict, conflicts}` or `{:ok, merged_key}`

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
- Supervised daemon process
- Test suite
