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

exec_in() {
    local container=$1
    shift
    podman exec -u testuser -e HOME=/home/testuser -e GNUPGHOME=/home/testuser/.gnupg -e CRISPKEY_DATA_DIR=/home/testuser/.config/crispkey -e CRISPKEY_MASTER_PASSWORD="$MASTER_PASSWORD" "$container" "$@"
}

check_container() {
    local container=$1
    if ! podman ps --format '{{.Names}}' | grep -q "^${container}$"; then
        error "Container $container is not running"
        return 1
    fi
    return 0
}

main() {
    log "Starting vault test setup..."
    if [ $1 != "NOBUILD" ]
    then
      "$SCRIPT_DIR/rebuild-containers.sh"
    fi
    
    check_container "$ALICE" || exit 1
    check_container "$BOB" || exit 1
    
    log "=== Alice status ==="
    exec_in "$ALICE" crispkey status 2>/dev/null || true
    log "=== Alice vaults ==="
    exec_in "$ALICE" expect -c "
        spawn crispkey unlock
        expect \"master password\"
        send \"$MASTER_PASSWORD\r\"
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
