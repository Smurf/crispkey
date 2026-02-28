#!/bin/bash
# test-setup.sh - Initialize vault system in both containers and generate test GPG keys
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

ALICE="crispkey-alice"
BOB="crispkey-bob"
SYNC_PASSWORD="testsync123"
MASTER_PASSWORD="testmaster123"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

error() {
    echo "[$(date '+%H:%M:%S')] ERROR: $1" >&2
}

check_container() {
    local container=$1
    if ! podman ps --format '{{.Names}}' | grep -q "^${container}$"; then
        error "Container $container is not running"
        return 1
    fi
    return 0
}

exec_in() {
    local container=$1
    shift
    podman exec -u testuser -e HOME=/home/testuser -e GNUPGHOME=/home/testuser/.gnupg -e CRISPKEY_DATA_DIR=/home/testuser/.config/crispkey "$container" "$@"
}

clear_state() {
    log "Clearing existing state..."
    
    # Clear volumes on host
    rm -rf "$PROJECT_DIR/test-volumes/alice/config"/* 2>/dev/null || true
    rm -rf "$PROJECT_DIR/test-volumes/bob/config"/* 2>/dev/null || true
    
    # Recreate directories
    mkdir -p "$PROJECT_DIR/test-volumes/alice/config"
    mkdir -p "$PROJECT_DIR/test-volumes/bob/config"
}

init_crispkey() {
    local container=$1
    log "Initializing vault system in $container..."
    
    # Use expect to automate password input
    exec_in "$container" expect -c "
        spawn crispkey init
        expect \"master password\"
        send \"$MASTER_PASSWORD\\r\"
        expect \"Confirm master password\"
        send \"$MASTER_PASSWORD\\r\"
        expect \"sync password\"
        send \"$SYNC_PASSWORD\\r\"
        expect \"Confirm sync password\"
        send \"$SYNC_PASSWORD\\r\"
        expect eof
    "
}

generate_test_key() {
    local container=$1
    local name=$2
    local email="${name,,}@test.local"
    
    log "Generating test GPG key in $container..."
    
    # Use GPG's quick-generate-key
    exec_in "$container" gpg --batch --yes --passphrase '' --quick-generate-key "$email" rsa2048 default never 2>&1 || {
        log "Warning: GPG key generation may have partially failed, continuing..."
    }
    
    # Get fingerprint
    local fp
    fp=$(exec_in "$container" gpg --list-keys --with-colons 2>/dev/null | grep "^fpr" | head -1 | cut -d: -f10)
    
    if [ -n "$fp" ]; then
        log "Generated key fingerprint: $fp"
        
        # Import to vault
        log "Importing key to vault..."
        exec_in "$container" expect -c "
            spawn crispkey unlock
            expect \"master password\"
            send \"$MASTER_PASSWORD\\r\"
            expect eof
        " 2>/dev/null || true
        
        exec_in "$container" crispkey vault import "$fp" 2>&1 || {
            log "Warning: Vault import may have failed"
        }
    fi
    
    # Verify key was created
    local key_count
    key_count=$(exec_in "$container" gpg --list-keys --with-colons 2>/dev/null | grep -c "^pub" || echo "0")
    log "GPG keys in $container: $key_count"
}

verify_daemon() {
    local container=$1
    log "Verifying daemon in $container..."
    
    sleep 1
    
    if exec_in "$container" sh -c "pgrep -f 'crispkey daemon' > /dev/null"; then
        log "Daemon running in $container"
        return 0
    else
        log "Starting daemon in $container..."
        exec_in "$container" crispkey daemon &
        sleep 2
    fi
}

main() {
    log "Starting vault test setup..."
    
    # Check containers are running
    check_container "$ALICE" || exit 1
    check_container "$BOB" || exit 1
    
    # Clear previous state
    clear_state
    
    # Initialize vault system in both containers
    init_crispkey "$ALICE"
    init_crispkey "$BOB"
    
    # Generate test keys only in Alice
    generate_test_key "$ALICE" "Alice Test"
    
    # Restart daemons to pick up new state
    log "Restarting daemons..."
    podman restart "$ALICE" "$BOB" 2>/dev/null || true
    sleep 2
    
    # Verify daemons are running
    verify_daemon "$ALICE"
    verify_daemon "$BOB"
    
    # Show status
    log "=== Alice status ==="
    exec_in "$ALICE" crispkey status 2>/dev/null || true
    log "=== Alice vaults ==="
    exec_in "$ALICE" expect -c "
        spawn crispkey unlock
        expect \"master password\"
        send \"$MASTER_PASSWORD\\r\"
        expect eof
    " 2>/dev/null || true
    exec_in "$ALICE" crispkey vault list 2>/dev/null || true
    
    log "=== Bob status ==="
    exec_in "$BOB" crispkey status 2>/dev/null || true
    
    log ""
    log "Setup complete!"
    log "Master password: $MASTER_PASSWORD"
    log "Sync password: $SYNC_PASSWORD"
}

main "$@"
