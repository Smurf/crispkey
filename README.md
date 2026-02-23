# crispkey

GPG key synchronization across devices using peer-to-peer discovery and sync.

## Features

- **P2P Discovery**: Find other devices on your local network via UDP multicast
- **Secure Key Wrapping**: Export keys encrypted with PBKDF2 + AES-256-GCM
- **Trust Database Sync**: Syncs GPG keys and ownertrust
- **Daemon Mode**: Background service for automatic discovery and sync

## Installation

### From Source

```bash
mix deps.get
mix escript.build
./crispkey init
```

### System-wide Install

```bash
# Build and install to /usr/local/bin
./install.sh
```

This also installs a systemd user service. See [Running as a Service](#running-as-a-service).

## Quick Start

```bash
# Initialize crispkey with a master passphrase
./crispkey init

# List your GPG keys
./crispkey keys

# Export a wrapped (encrypted) key for backup or transfer
./crispkey wrap <fingerprint>

# Import a wrapped key
./crispkey unwrap crispkey_<fingerprint>.wrapped
```

## Discovery & Sync

### How It Works

crispkey uses UDP multicast for peer discovery:

1. **Daemon** (`crispkey daemon`) runs on each device, listening on port 4830
2. **Discoverer** sends a multicast announcement to `224.0.0.251:4830`
3. All daemons on the network receive the announcement and respond with their device info
4. The discoverer collects responses and displays available peers

```
┌─────────────┐                    ┌─────────────┐
│  Device A   │                    │  Device B   │
│             │                    │             │
│  daemon ────┼──── multicast ────►│  daemon     │
│             │                    │  (responds) │
│             │◄──── unicast ──────┤             │
│  discover   │                    │             │
└─────────────┘                    └─────────────┘
```

### Starting the Daemon

On each device you want to sync with:

```bash
./crispkey daemon
```

Output:
```
Starting crispkey daemon...
Device ID: d60d84530ad8ab5b
Listening for discovery on port 4830
Listening for sync on port 4829
Press Ctrl+C to stop
```

For production use, run as a systemd service or background process:

```bash
# Run in background
nohup ./crispkey daemon > /var/log/crispkey.log 2>&1 &
```

### Running as a Service

crispkey includes a systemd user service for automatic startup.

**Install the service:**

```bash
# Build and install
./install.sh

# Or manually:
mkdir -p ~/.config/systemd/user
cp contrib/crispkey.service ~/.config/systemd/user/
systemctl --user daemon-reload
```

**Manage the service:**

```bash
# Start now
systemctl --user start crispkey

# Enable at login
systemctl --user enable crispkey

# Check status
systemctl --user status crispkey

# View logs
journalctl --user -u crispkey -f
```

**Linger for headless servers:**

To keep the service running when you're not logged in:

```bash
sudo loginctl enable-linger $USER
```

### Discovering Peers

From any device on the same network:

```bash
./crispkey discover
```

Output:
```
Discovering devices (5s)...
Make sure 'crispkey daemon' is running on other devices.
Found 2 device(s):
  a1b2c3d4e5f6g7h8 @ 192.168.1.100:4829
  i9j0k1l2m3n4o5p6 @ 192.168.1.101:4829
```

Specify a custom timeout (in seconds):

```bash
./crispkey discover 10
```

### Pairing Devices

After discovering peers, pair with them by device ID or IP address:

**By device ID (recommended):**

```bash
./crispkey pair a1b2c3d4e5f6g7h8
```

**By IP address:**

```bash
./crispkey pair 192.168.1.100
```

Output:
```
Pairing with 192.168.1.100...
Connected to peer
Paired successfully
```

### Syncing Keys

Sync with all paired devices:

```bash
./crispkey sync
```

Or sync with a specific device:

```bash
./crispkey sync d60d84530ad8ab5b
```

## Command Reference

```
crispkey - GPG key synchronization

Usage:
  crispkey init              Initialize crispkey
  crispkey status            Show sync status
  crispkey keys              List local GPG keys
  crispkey devices           List paired devices
  crispkey daemon            Start background sync daemon
  crispkey discover [sec]    Find devices on network
  crispkey pair <id|host>    Pair with a device (by ID or IP)
  crispkey sync [device]     Sync keys with device(s)
  crispkey export <fp>       Export key (armored)
  crispkey wrap <fp>         Export wrapped (encrypted) key
  crispkey unwrap <file>     Import wrapped key
```

## Key Wrapping

### Export (Wrap)

Create an encrypted backup of a key:

```bash
./crispkey wrap ABC123DEF456...
```

This creates `crispkey_ABC123DEF456....wrapped` containing:
- Public key
- Secret key
- Trust database
- Key fingerprint

The file is encrypted with AES-256-GCM using a key derived from your passphrase via PBKDF2 (600,000 iterations).

### Import (Unwrap)

Import a wrapped key:

```bash
./crispkey unwrap crispkey_ABC123DEF456....wrapped
```

You'll be prompted for the wrapping passphrase.

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 4829 | TCP | Sync protocol (key exchange) |
| 4830 | UDP | Discovery (multicast) |

Ensure these ports are open on your firewall for local network communication.

## Multicast Address

Discovery uses multicast address `224.0.0.251` (link-local multicast). This should work on most local networks without special configuration.

## Data Storage

crispkey stores data in:

```
~/.config/crispkey/
├── device_id      # Unique device identifier
└── state.json     # Paired devices, sync history
```

GPG keys remain in the standard `~/.gnupg` directory.

## Security

- **Key Wrapping**: Uses PBKDF2 (600k iterations) + AES-256-GCM
- **Passphrase**: Never stored; derived key cached only in memory
- **Transport**: Sync traffic is encrypted with per-session keys
- **Self-Discovery Prevention**: Device ignores its own discovery announcements
- **Type Safety**: All wire protocol messages use typed structs with safe atomization to prevent DoS attacks

## Troubleshooting

### No devices found

1. Ensure `crispkey daemon` is running on other devices
2. Check firewall allows UDP port 4830
3. Verify devices are on the same network segment (multicast may not route)

### Port already in use

If port 4829/4830 are in use, configure different ports in `config/config.exs`:

```elixir
config :crispkey,
  sync_port: 4831,
  discovery_port: 4832
```

## Development

```bash
# Get dependencies
mix deps.get

# Build escript
mix escript.build

# Run type checking
mix dialyzer

# Run code quality checks
mix credo

# Run tests
mix test
```

## License

GPL v3
