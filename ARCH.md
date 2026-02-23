# Crispkey Architecture

GPG key synchronization across devices using peer-to-peer discovery and sync.

## Overview

Crispkey enables syncing GPG keys between devices on a local network without a central server. It uses:

- **UDP Multicast** for peer discovery
- **TCP** for key sync protocol
- **PBKDF2 + AES-256-GCM** for key wrapping
- **SHA256** for sync password authentication

## Repository Structure

```
crispkey/
├── lib/crispkey/
│   ├── application.ex           # OTP application supervisor
│   ├── cli.ex                   # CLI command dispatcher
│   ├── crispkey.ex              # Core module (device_id, config access)
│   ├── crypto/
│   │   └── key_wrapper.ex       # PBKDF2 key derivation, AES-GCM wrapping
│   ├── gpg/
│   │   ├── interface.ex         # GPG CLI wrapper (list, export, import)
│   │   └── types.ex             # Key, UID, Subkey structs with typespecs
│   ├── merge/
│   │   └── engine.ex            # Key merge conflict detection
│   ├── store/
│   │   ├── local_state.ex       # Persistent state (peers, sync history)
│   │   ├── peers.ex             # Discovered peers cache
│   │   └── types.ex             # State, Peer structs with typespecs
│   └── sync/
│       ├── connection.ex        # Client-side sync connection
│       ├── daemon.ex            # Background discovery listener
│       ├── discovery.ex         # UDP multicast discovery
│       ├── listener.ex          # TCP sync listener (server)
│       ├── message.ex           # Wire protocol message structs
│       ├── peer.ex              # Per-connection peer handler (server)
│       └── protocol.ex          # Wire protocol encoding/decoding
├── config/config.exs            # Application config
├── mix.exs                      # Project definition
├── contrib/
│   └── crispkey.service        # Systemd user service
├── install.sh                   # Build and install script
└── README.md
```

## Core Components

### CLI (`lib/crispkey/cli.ex`)

Entry point for all commands. Dispatches to appropriate modules.

**Commands:**
- `init` - Initialize device, set master passphrase and sync password
- `status` - Show device ID, paired devices, last sync
- `keys` - List local GPG keys via GPG Interface
- `devices` - List paired devices from LocalState
- `daemon` - Start Listener + Discovery Daemon
- `discover` - One-shot UDP multicast discovery
- `pair` - Connect to peer, exchange HELLO, store in LocalState
- `sync` - Authenticate and sync keys with peer
- `wrap`/`unwrap` - Export/import encrypted key bundles

### GPG Interface (`lib/crispkey/gpg/interface.ex`)

Wraps `gpg` CLI for key operations. Returns typed structs defined in `types.ex`.

**Structs:**
- `Crispkey.GPG.Key` - GPG key with fingerprint, key_id, algorithm, bits, uids, subkeys, type
- `Crispkey.GPG.UID` - User ID with string, created_at, expires_at
- `Crispkey.GPG.Subkey` - Subkey with fingerprint, algorithm, bits, timestamps

**Functions:**
- `list_public_keys/0` - Returns `{:ok, [Key.t()]}`, parses `gpg --list-keys --with-colons`
- `list_secret_keys/0` - Returns `{:ok, [Key.t()]}`, parses `gpg --list-secret-keys --with-colons`
- `export_public_key/1` - `gpg --armor --export <fp>`
- `export_secret_key/1` - `gpg --armor --export-secret-keys <fp>`
- `import_key/1` - `gpg --import` (uses Port for stdin)
- `export_trustdb/0` - `gpg --export-ownertrust`
- `import_trustdb/1` - `gpg --import-ownertrust`

### Crypto (`lib/crispkey/crypto/key_wrapper.ex`)

Key wrapping using PBKDF2 + AES-256-GCM.

**Wrap format (binary):**
```
[32 bytes salt][12 bytes nonce][16 bytes auth tag][ciphertext]
```

**Parameters:**
- PBKDF2 with SHA256, 600,000 iterations
- AES-256-GCM for encryption
- Random salt and nonce per wrap

**Functions:**
- `wrap(plaintext, passphrase)` -> wrapped binary
- `unwrap(wrapped, passphrase)` -> `{:ok, plaintext}` | `{:error, :decryption_failed}`

### Message (`lib/crispkey/sync/message.ex`)

Typed message structs for wire protocol. All messages are JSON with 4-byte length prefix.

**Message structs:**
- `Hello` - Device handshake (device_id, version)
- `Auth` - Sync password hash (password_hash)
- `AuthOk` / `AuthFail` - Authentication result
- `Inventory` - List of keys (keys array)
- `Request` - Request keys by fingerprint
- `KeyData` - Key data transfer (fingerprint, key_type, data)
- `TrustData` - Trust database transfer
- `Ack` - Acknowledgment
- `Goodbye` - Connection close

**Key functions:**
- `encode/1` - Convert struct to wire format
- `decode/1` - Parse wire data to struct (safe atomization)
- `to_wire/1` - Convert struct to JSON-compatible map
- `from_wire/1` - Parse JSON map to struct with validation

### Protocol (`lib/crispkey/sync/protocol.ex`)

Wire protocol encoding/decoding. Delegates to Message module.

**Message format:**
```
[4 bytes: length as 32-bit big-endian][JSON payload]
```

**Security:** Uses explicit key atomization to prevent atom table exhaustion attacks. Never uses `keys: :atoms` with untrusted input.

### Discovery (`lib/crispkey/sync/discovery.ex`)

One-shot UDP multicast discovery for finding peers.

**Process:**
1. Open ephemeral UDP socket
2. Send announcement to multicast `224.0.0.251:4830`
3. Collect responses for timeout duration
4. Return list of discovered peers

**Announcement format:**
```json
{"service":"_crispkey._tcp.local","id":"<device_id>","port":4829}
```

### Daemon (`lib/crispkey/sync/daemon.ex`)

Background GenServer for responding to discovery requests.

**Process:**
1. Listen on UDP port 4830 with multicast membership
2. Receive announcements
3. Respond with own announcement to sender's IP:port
4. Ignores own announcements (same device_id)

### Listener (`lib/crispkey/sync/listener.ex`)

TCP listener for incoming sync connections.

**Process:**
1. Listen on TCP port 4829
2. Accept connections in loop
3. For each connection, start Peer process
4. Transfer socket ownership to Peer via `controlling_process/2`

### Peer (`lib/crispkey/sync/peer.ex`)

Per-connection GenServer handling the server side of sync.

**Lifecycle:**
1. `init` - Start handshake via `handle_continue`
2. Handshake - Receive HELLO, send HELLO back
3. Set socket to active mode
4. Handle incoming messages via `handle_info({:tcp, ...})`

**Message handling:**
- `auth` - Verify password hash, respond auth_ok/auth_fail, set authenticated flag
- `inventory` - Send back local inventory
- `request` - If authenticated, export and send requested keys
- `key_data` - Import received keys

### Connection (`lib/crispkey/sync/connection.ex`)

Client-side sync connection. Direct TCP connection without GenServer.

**Sync flow:**
1. `connect(host)` - TCP connect, handshake (send/receive HELLO)
2. `sync(socket, password)` - Full sync operation
   - `authenticate` - Send password hash, wait for auth_ok
   - `exchange_inventory` - Send inventory, receive remote inventory
   - `find_needed_keys` - Compare local vs remote (fingerprint + type)
   - `request_key` - For each needed key, send request, receive key_data
   - Wait for ACK

### Local State (`lib/crispkey/store/local_state.ex`)

Persistent state GenServer backed by `~/.config/crispkey/state.json`. Uses typed structs from `types.ex`.

**State struct (`Crispkey.Store.State`):**
```elixir
%Crispkey.Store.State{
  device_id: "d60d84530ad8ab5b",
  initialized: true,
  sync_password_hash: "base64_sha256_hash",
  peers: %{
    "0e22bd906189c13a" => %Crispkey.Store.Peer{id: "...", host: "192.168.1.40", port: 4829, paired_at: ~U[...]}
  },
  key_syncs: %{
    "fingerprint" => %{"peer_id" => ~U[...]}
  },
  last_sync: ~U[...]
}
```

**Peer struct (`Crispkey.Store.Peer`):**
- `id` - Device identifier (string)
- `host` - IP address or hostname
- `port` - Sync port number
- `paired_at` - DateTime of pairing

**Functions:**
- `get_state/0`, `update_state/1`
- `add_peer/1`, `remove_peer/1`, `get_peers/0`
- `set_sync_password/1`, `verify_sync_password/1`, `verify_sync_password_hash/1`
- `record_sync/3`

### Peers Cache (`lib/crispkey/store/peers.ex`)

Transient cache for discovered peers (not paired).

**File:** `~/.config/crispkey/discovered_peers.json`

**Used for:** Looking up IP address when pairing by device_id.

### Merge Engine (`lib/crispkey/merge/engine.ex`)

Conflict detection for key merging (currently basic).

**Detects conflicts:**
- UIDs added on both sides
- Subkeys added on both sides
- Expiry changed on both sides

**Merge strategy:** Add non-conflicting components, prompt for conflicts.

## Data Flows

### Init Flow

```
User runs: crispkey init
         │
         ▼
┌─────────────────────┐
│ Create ~/.config/   │
│ crispkey/           │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Prompt master       │
│ passphrase          │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Prompt sync password│
│ (for remote auth)   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Test wrap/unwrap    │
│ with passphrase     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Store sync password │
│ hash in state.json  │
└─────────────────────┘
```

### Discovery Flow

```
Device B                      Network                    Device A (daemon)
    │                            │                              │
    │ ──── UDP multicast ──────► │                              │
    │      announcement          │                              │
    │                            │ ──── UDP unicast ──────────► │
    │                            │      announcement            │
    │                            │                              │
    │                            │ ◄─── UDP unicast ─────────── │
    │ ◄─── UDP response ──────── │      response               │
    │                            │                              │
    ▼                            │                              │
Save to discovered_peers.json   │                              │
```

### Pairing Flow

```
Device B (client)                TCP                 Device A (server/daemon)
    │                            │                              │
    │ ─── connect :4829 ────────►│                              │
    │                            │                              │
    │ ─── HELLO ────────────────►│ ─── start Peer ────────────►│
    │                            │                              │
    │◄── HELLO ──────────────────│◄── send HELLO ───────────── │
    │                            │                              │
    ▼                            │                              │
Save peer to state.json          │                              │
```

### Sync Flow

```
Device B (client)                TCP                 Device A (server)
    │                            │                              │
    │ ─── AUTH (password hash)──►│                              │
    │                            │ ─── verify hash ────────────►│
    │◄── AUTH_OK ────────────────│◄── auth_ok ───────────────── │
    │                            │                              │
    │ ─── INVENTORY ────────────►│                              │
    │                            │ ─── send inventory ─────────►│
    │◄── INVENTORY ──────────────│◄── INVENTORY ─────────────── │
    │                            │                              │
    ▼                            │                              │
Calculate needed keys            │                              │
    │                            │                              │
    │ ─── REQUEST (fingerprints)►│                              │
    │                            │ ─── if authenticated: ──────►│
    │                            │     export keys              │
    │◄── KEY_DATA (public) ──────│◄── send KEY_DATA ─────────── │
    │◄── KEY_DATA (secret) ──────│◄── send KEY_DATA ─────────── │
    │◄── ACK ────────────────────│◄── send ACK ──────────────── │
    │                            │                              │
    ▼                            │                              │
Import keys via GPG              │                              │
```

### Key Wrap/Unwrap Flow

```
wrap <fingerprint>
    │
    ▼
┌──────────────────────┐
│ Export public key    │
│ Export secret key    │
│ Export trustdb       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Bundle as JSON       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Prompt passphrase    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Derive key via       │
│ PBKDF2 (600k iter)   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Encrypt with         │
│ AES-256-GCM          │
└──────────┬───────────┘
           │
           ▼
Write .wrapped file
```

## Configuration

**Config file:** `config/config.exs`

```elixir
config :crispkey,
  gpg_homedir: "~/.gnupg",
  data_dir: "~/.config/crispkey",
  sync_port: 4829,      # TCP sync
  discovery_port: 4830  # UDP multicast
```

**Data directory:** `~/.config/crispkey/`
- `device_id` - 16 hex chars, random
- `state.json` - Persistent state
- `discovered_peers.json` - Transient peer cache

## Security Model

### Master Passphrase
- Used for wrapping key bundles
- Never stored, only used for PBKDF2 key derivation
- Separate from GPG key passphrases

### Sync Password
- Used for authenticating sync requests
- Stored as SHA256 hash in `state.json`
- Must be entered on client when syncing
- Allows remote device to access secret keys

### Key Wrapping
- PBKDF2-SHA256 with 600,000 iterations
- AES-256-GCM encryption
- Unique salt and nonce per wrap
- No key material stored unencrypted

### Transport
- TCP connections are unencrypted (plaintext)
- Secret keys only sent after password authentication
- Consider adding TLS for production use

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4829 | TCP | Sync protocol |
| 4830 | UDP | Discovery multicast |

## Dependencies

From `mix.exs`:
- `jason` - JSON encoding/decoding
- `ranch` - TCP acceptor pool (for Listener)
- `norm` - Data validation and contracts

Dev dependencies:
- `dialyxir` - Static type checking with dialyzer
- `credo` - Code quality linting
- `proper` - Property-based testing

Built-in Erlang:
- `:crypto` - PBKDF2, AES-GCM, SHA256
- `:gen_tcp` - TCP connections
- `:gen_udp` - UDP multicast

## Type Safety

The codebase uses typed structs and `@spec` annotations throughout:

**GPG Types (`lib/crispkey/gpg/types.ex`):**
- `Crispkey.GPG.Key` - Public/secret key representation
- `Crispkey.GPG.UID` - User identity
- `Crispkey.GPG.Subkey` - Subkey information

**Store Types (`lib/crispkey/store/types.ex`):**
- `Crispkey.Store.State` - Application state
- `Crispkey.Store.Peer` - Paired device info

**Sync Messages (`lib/crispkey/sync/message.ex`):**
- All wire protocol messages as typed structs (`Hello`, `Auth`, `Inventory`, etc.)

**Security:** JSON parsing uses explicit key atomization to prevent atom table exhaustion DoS attacks. Never uses `keys: :atoms` with untrusted input.

## Type Safety

The codebase uses typed structs and `@spec` annotations throughout:

**GPG Types (`lib/crispkey/gpg/types.ex`):**
- `Crispkey.GPG.Key` - Public/secret key representation
- `Crispkey.GPG.UID` - User identity
- `Crispkey.GPG.Subkey` - Subkey information

**Store Types (`lib/crispkey/store/types.ex`):**
- `Crispkey.Store.State` - Application state
- `Crispkey.Store.Peer` - Paired device info

**Sync Messages (`lib/crispkey/sync/message.ex`):**
- All wire protocol messages as typed structs

**Security:** JSON parsing uses explicit key atomization to prevent atom table exhaustion DoS attacks. Never use `keys: :atoms` with untrusted input.

## Known Limitations

1. **No TLS** - Sync traffic is plaintext (authentication happens in protocol)
2. **LAN only** - Discovery uses multicast, won't route across subnets
3. **No incremental sync** - Full key data sent each time
4. **No key deletion sync** - Only adds keys, doesn't remove
5. **Single sync direction** - Client pulls from server, not bidirectional

## Testing

For iterative testing with isolated Podman containers, see [TESTING.md](TESTING.md).

The testing environment provides:
- Two containers (`alice` and `bob`) in an isolated network
- Automated setup, pairing, and sync tests
- Watch mode for continuous testing during development

## Future Work

- TLS encryption for transport
- Relay server for remote sync
- Incremental sync (only changed keys)
- Bidirectional sync
- Key deletion propagation
- Conflict resolution UI
- Multiple GPG homedirs
- Trust database full sync
- Key signature verification
