#!/bin/bash
# rebuild-containers.sh - Rebuild containers and initialize vault system
# This script is called by test scripts to set up the test environment

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

exec_in() {
    local container=$1
    shift
    podman exec -u testuser -e HOME=/home/testuser -e GNUPGHOME=/home/testuser/.gnupg -e CRISPKEY_DATA_DIR=/home/testuser/.config/crispkey -e CRISPKEY_MASTER_PASSWORD="$MASTER_PASSWORD" "$container" "$@"
}

create_network() {
    if ! podman network ls | grep -q "crispkey-test"; then
        log "Creating podman network..."
        podman network create crispkey-test
    fi
}

clear_volumes() {
    log "Clearing volumes..."
    rm -rf "$PROJECT_DIR/test-volumes/alice/config"/* 2>/dev/null || true
    rm -rf "$PROJECT_DIR/test-volumes/alice/gnupg"/* 2>/dev/null || true
    rm -rf "$PROJECT_DIR/test-volumes/bob/config"/* 2>/dev/null || true
    rm -rf "$PROJECT_DIR/test-volumes/bob/gnupg"/* 2>/dev/null || true
    
    mkdir -p "$PROJECT_DIR/test-volumes/alice/config"
    mkdir -p "$PROJECT_DIR/test-volumes/alice/gnupg"
    mkdir -p "$PROJECT_DIR/test-volumes/bob/config"
    mkdir -p "$PROJECT_DIR/test-volumes/bob/gnupg"
    
    chmod -R 755 "$PROJECT_DIR/test-volumes/alice"
    chmod -R 755 "$PROJECT_DIR/test-volumes/bob"
}

stop_containers() {
    log "Stopping containers..."
    podman stop "$ALICE" "$BOB" 2>/dev/null || true
    podman rm "$ALICE" "$BOB" 2>/dev/null || true
}

rebuild_image() {
    log "Rebuilding container image..."
    podman-compose -f $PROJECT_DIR/docker-compose.podman.yml build --no-cache
}

start_containers() {
    log "Starting containers..."
    podman-compose -f "$PROJECT_DIR/docker-compose.podman.yml" up -d
    sleep 3
}

init_crispkey() {
    local container=$1
    log "Initializing vault system in $container..."
    
    exec_in "$container" expect -c "
        spawn crispkey init
        expect \"master password\"
        send \"$MASTER_PASSWORD\r\"
        expect \"Confirm master password\"
        send \"$MASTER_PASSWORD\r\"
        expect \"sync password\"
        send \"$SYNC_PASSWORD\r\"
        expect \"Confirm sync password\"
        send \"$SYNC_PASSWORD\r\"
        expect eof
    "
}

generate_test_key() {
    local container=$1
    local name=$2
    local email="${name,,}@test.local"
    
    log "Generating test GPG key in $container..."
    
    exec_in "$container" gpg --batch --yes --passphrase '' --quick-generate-key "$email" rsa2048 default never 2>&1 || {
        log "Warning: GPG key generation may have partially failed, continuing..."
    }
    
    local fp
    fp=$(exec_in "$container" gpg --list-keys --with-colons 2>/dev/null | grep "^fpr" | head -1 | cut -d: -f10)
    
    if [ -n "$fp" ]; then
        log "Generated key fingerprint: $fp"
        
        log "Importing key to vault..."
        exec_in "$container" crispkey vault import "$fp" 2>&1 || {
            log "Warning: Vault import may have failed"
        }
    fi
    
    local key_count
    key_count=$(exec_in "$container" gpg --list-keys --with-colons 2>/dev/null | grep -c "^pub" || echo "0")
    log "GPG keys in $container: $key_count"
}

restart_daemons() {
    log "Restarting daemons..."
    podman restart "$ALICE" "$BOB" 2>/dev/null || true
    sleep 2
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
    log "Starting container rebuild and initialization..."
    log "================================================"
    
    create_network
    stop_containers
    clear_volumes
    rebuild_image
    start_containers
    
    init_crispkey "$ALICE"
    init_crispkey "$BOB"
    
    generate_test_key "$ALICE" "Alice Test"
    
    restart_daemons
    
    verify_daemon "$ALICE"
    verify_daemon "$BOB"
    
    log "Waiting for daemons to be fully ready..."
    sleep 3
    
    log "Container rebuild and initialization complete!"
    log "Master password: $MASTER_PASSWORD"
    log "Sync password: $SYNC_PASSWORD"
}

main "$@"
