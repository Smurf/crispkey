# crispkey

GPG key synchronization across devices using encrypted vaults and peer-to-peer sync.

## Features

- **Encrypted Vaults**: Keys stored in individually encrypted vault files
- **Separate Passwords**: Master password for vaults, sync password for authentication
- **Encrypted Transport**: All sync communication encrypted with session keys
- **P2P Discovery**: Find other devices on your local network via UDP multicast
- **Incremental Sync**: Only transfer changed vaults

## Installation

### From Source

```bash
mix deps.get
mix escript.build
./crispkey init
```

### System-wide Install

```bash
./install.sh
```

## Quick Start

```bash
# Initialize vault system
./crispkey init

# Unlock vaults for operations
./crispkey unlock

# Import your GPG keys to vaults
./crispkey vault import <fingerprint>

# List vaults
./crispkey vault list
```

## Security Model

```
┌─────────────────────────────────────────────────────────────┐
│  Master Password → PBKDF2(600k iter) → Master Key           │
│                         │                                   │
│                         ▼                                   │
│              Vault Key (per vault via HKDF)                 │
│                         │                                   │
│                         ▼                                   │
│              AES-256-GCM Encrypted Vault                    │
├─────────────────────────────────────────────────────────────┤
│  Sync Password → HKDF(session_id) → Session Key             │
│                         │                                   │
│                         ▼                                   │
│              AES-256-GCM Encrypted Transport                │
└─────────────────────────────────────────────────────────────┘
```

**Key Benefits:**
- Vaults remain encrypted during sync (no re-encryption)
- Compromised sync password doesn't expose vault contents
- Each vault uses a unique derived key

## Vault Commands

```bash
# Initialize vault system (set master + sync passwords)
crispkey init

# Unlock vaults with master password
crispkey unlock

# Lock vaults (clear master key from memory)
crispkey lock

# List vaults
crispkey vault list

# Import GPG key to vault
crispkey vault import <fingerprint>

# Export vault to GPG keyring
crispkey vault export <fingerprint>

# Delete a vault
crispkey vault delete <fingerprint>
```

## Sync Commands

```bash
# Discover devices on network
crispkey discover

# Pair with a device
crispkey pair <device_id|ip>

# Sync vaults with paired device
crispkey sync [device_id]
```

## Discovery & Sync

### How It Works

1. **Daemon** runs on each device, listening for discovery and sync
2. **Discover** sends multicast announcement to find peers
3. **Pair** exchanges device IDs for trust establishment
4. **Sync** exchanges manifests and transfers encrypted vaults

```
┌─────────────┐                    ┌─────────────┐
│  Device A   │                    │  Device B   │
│             │                    │             │
│  daemon ────┼──── multicast ────►│  daemon     │
│             │◄──── response ─────┤             │
│             │                    │             │
│  unlock     │                    │  unlock     │
│  sync ──────┼── encrypted channel─┼─► receive  │
│             │                    │  vaults     │
└─────────────┘                    └─────────────┘
```

### Starting the Daemon

```bash
crispkey daemon
```

For production, run as a systemd service:

```bash
systemctl --user enable crispkey
systemctl --user start crispkey
```

## Data Storage

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

## Command Reference

```
crispkey - GPG key synchronization with encrypted vaults

Vault Commands:
  init              Initialize vault system
  unlock            Unlock vaults with master password
  lock              Lock vaults
  vault list        List vaults
  vault import <fp> Import GPG key to vault
  vault export <fp> Export vault to GPG keyring
  vault delete <fp> Delete a vault

Sync Commands:
  status            Show sync status
  keys              List GPG keys in keyring
  devices           List paired devices
  daemon            Start background sync daemon
  discover [sec]    Find devices on network
  pair <id|host>    Pair with a device
  sync [device]     Sync vaults with device(s)

Legacy Commands:
  export <fp>       Export key (armored)
  wrap <fp>         Export wrapped key
  unwrap <file>     Import wrapped key
```

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4829 | TCP | Sync protocol (encrypted) |
| 4830 | UDP | Discovery (multicast) |

## Security Properties

| Threat | Protection |
|--------|------------|
| Vault file stolen | Encrypted with master key (PBKDF2 600k iter) |
| Sync traffic intercepted | Encrypted with session key |
| Sync password compromised | Can sync, but can't read vaults |
| Master password compromised | Can read vaults, but can't impersonate for sync |
| One vault compromised | Others use different HKDF-derived keys |

## Troubleshooting

### Vaults locked error

Unlock vaults before operations:

```bash
crispkey unlock
```

### Sync authentication failed

Ensure you're using the *remote* device's sync password:

```bash
crispkey sync
# Enter remote device's sync password: (the OTHER node's password)
```

### No devices found

1. Ensure `crispkey daemon` is running on other devices
2. Check firewall allows UDP port 4830
3. Verify devices are on the same network segment

## Development

```bash
mix deps.get
mix escript.build
mix compile --warnings-as-errors
```

## License

GPL v3
