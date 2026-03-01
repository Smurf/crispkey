# crispkey

**DISCLAIMER**

This repository is purely vibe coded. I have no clue how this actually works. Do not use this in production under any circumstance.

GPG key synchronization across devices using encrypted vaults and peer-to-peer sync.

## Features

- **Encrypted Vaults**: Keys stored in individually encrypted vault files
- **Separate Passwords**: Master password for vaults, sync password for authentication
- **Hardware Key Support**: Unlock vaults with YubiKey or FIDO2 device
- **Encrypted Transport**: All sync communication encrypted with session keys
- **P2P Discovery**: Find other devices on your local network via UDP multicast
- **Incremental Sync**: Only transfer changed vaults

## Installation

### Prerequisites

#### For Password-based Authentication
- Elixir/Erlang

#### For YubiKey/FIDO2 Authentication
- **Linuxsudo apt install f**: `ido2-tools` or `sudo dnf install fido2-tools`
- **macOS**: `brew install libfido2`
- A FIDO2/YubiKey 5 series device

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
┌─────────────────────────────────────────────────────────────────┐
│  Master Password → PBKDF2(600k iter) → Master Key              │
│                         │                                       │
│                         ▼                                       │
│              Vault Key (per vault via HKDF)                     │
│                         │                                       │
│                         ▼                                       │
│              AES-256-GCM Encrypted Vault                         │
├─────────────────────────────────────────────────────────────────┤
│  YubiKey Path (optional):                                       │
│  1. Generate random DEK                                         │
│  2. Wrap master key with DEK                                     │
│  3. Store DEK wrapped by FIDO2 credential                       │
│  4. Unlock requires PIN + touch                                  │
├─────────────────────────────────────────────────────────────────┤
│  Sync Password → HKDF(session_id) → Session Key                 │
│                         │                                       │
│                         ▼                                       │
│              AES-256-GCM Encrypted Transport                    │
└─────────────────────────────────────────────────────────────────┘
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

# Unlock vaults with YubiKey (if enrolled)
crispkey unlock
# Press Enter when prompted to use YubiKey

# Or directly:
crispkey yubikey unlock

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

## YubiKey Commands

```bash
# Check YubiKey/FIDO2 status
crispkey yubikey status

# Enroll a new YubiKey (vaults must be unlocked first)
crispkey yubikey enroll

# Unlock with YubiKey directly
crispkey yubikey unlock

# List enrolled credentials
crispkey yubikey list

# Remove enrolled credential
crispkey yubikey remove <credential_id>
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
├── wrapped_key               # FIDO2 credential storage
├── wrapped_key.enc          # Encrypted master key (YubiKey path)
└── state.json               # Paired devices, sync history
```

## Command Reference

```
crispkey - GPG key synchronization with encrypted vaults

Vault Commands:
  init              Initialize vault system
  unlock            Unlock vaults (password or YubiKey)
  lock              Lock vaults
  vault list        List vaults
  vault import <fp> Import GPG key to vault
  vault export <fp> Export vault to GPG keyring
  vault delete <fp> Delete a vault

YubiKey Commands:
  yubikey enroll      Enroll a new YubiKey
  yubikey unlock      Unlock with YubiKey
  yubikey list        List enrolled credentials
  yubikey remove <id> Remove credential
  yubikey status      Show YubiKey status

Sync Commands:
  status            Show sync status
  keys              List GPG keys in keyring
  devices           List paired devices
  daemon            Start background sync daemon
  discover [sec]    Find devices on network
  pair <id|host>    Pair with a device
  sync [device]     Sync vaults with device(s)
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
| Password brute force | YubiKey path requires physical device |

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
