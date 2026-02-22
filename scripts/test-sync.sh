#!/bin/bash
# test-sync.sh - Test key synchronization between containers
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

ALICE="crispkey-alice"
BOB="crispkey-bob"
SYNC_PASSWORD="test-sync-password-123"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

error() {
    echo "[$(date '+%H:%M:%S')] ERROR: $1" >&2
}

exec_in() {
    local container=$1
    shift
    podman exec -u testuser -e HOME=/home/testuser -e GNUPGHOME=/home/testuser/.gnupg "$container" "$@"
}

get_device_id() {
    local container=$1
    exec_in "$container" cat /home/testuser/.config/crispkey/device_id 2>/dev/null || echo ""
}

get_bob_ip() {
    podman inspect "$BOB" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

get_alice_ip() {
    podman inspect "$ALICE" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

count_keys() {
    local container=$1
    local output
    output=$(exec_in "$container" crispkey keys 2>/dev/null)
    # Count lines with key IDs (16 hex chars followed by algorithm)
    echo "$output" | grep -E '^\s+[A-F0-9]{16}' | wc -l | tr -d ' '
}

get_alice_fingerprints() {
    exec_in "$ALICE" crispkey keys 2>/dev/null | grep -oE '[A-F0-9]{16}' | sort -u || true
}

test_sync() {
    log "Testing key sync..."
    
    # Get Alice's device ID (Bob will sync FROM Alice)
    local alice_id
    alice_id=$(get_device_id "$ALICE")
    
    if [ -z "$alice_id" ]; then
        error "Could not get Alice's device ID"
        return 1
    fi
    
    # Count keys before sync
    local alice_keys_before bob_keys_before
    alice_keys_before=$(count_keys "$ALICE")
    bob_keys_before=$(count_keys "$BOB")
    
    log "Keys before sync - Alice: $alice_keys_before, Bob: $bob_keys_before"
    
    if [ "$alice_keys_before" -eq 0 ]; then
        error "Alice has no keys to sync"
        return 1
    fi
    
    # Run sync FROM Bob TO Alice (Bob pulls keys from Alice)
    # The sync command pulls keys FROM the peer TO local
    log "Running sync from Bob (pulling from Alice)..."
    
    # First Bob needs to pair with Alice
    local alice_ip
    alice_ip=$(get_alice_ip)
    
    log "Pairing Bob with Alice first..."
    exec_in "$BOB" crispkey pair "$alice_ip" 2>&1 || true
    
    # The sync command needs the password
    local sync_output
    sync_output=$(exec_in "$BOB" expect -c "
        spawn crispkey sync $alice_id
        expect \"Sync password:\"
        send \"$SYNC_PASSWORD\\r\"
        expect eof
    " 2>&1 || true)
    
    log "Sync output: $sync_output"
    
    # Count keys after sync
    sleep 1
    local bob_keys_after
    bob_keys_after=$(count_keys "$BOB")
    
    log "Keys after sync - Bob: $bob_keys_after"
    
    if [ "$bob_keys_after" -ge "$alice_keys_before" ]; then
        log "Sync: PASS - Keys transferred to Bob"
        return 0
    else
        error "Sync: FAIL - Keys not transferred (expected >= $alice_keys_before, got $bob_keys_after)"
        return 1
    fi
}

test_key_integrity() {
    log "Testing key integrity..."
    
    # Get fingerprints from both containers
    local alice_fps bob_fps
    alice_fps=$(get_alice_fingerprints | sort)
    bob_fps=$(exec_in "$BOB" crispkey keys 2>/dev/null | grep -oE '[A-F0-9]{16}' | sort -u)
    
    if [ -z "$alice_fps" ]; then
        error "No fingerprints found in Alice"
        return 1
    fi
    
    log "Alice fingerprints:"
    echo "$alice_fps" | while read fp; do
        log "  $fp"
    done
    
    log "Bob fingerprints:"
    echo "$bob_fps" | while read fp; do
        log "  $fp"
    done
    
    # Check if all Alice's keys are in Bob
    local all_found=true
    while read fp; do
        if ! echo "$bob_fps" | grep -q "$fp"; then
            error "Key $fp not found in Bob"
            all_found=false
        fi
    done <<< "$alice_fps"
    
    if [ "$all_found" = true ]; then
        log "Integrity: PASS - All keys match"
        return 0
    else
        error "Integrity: FAIL - Key mismatch"
        return 1
    fi
}

main() {
    log "Starting sync tests..."
    
    local failures=0
    
    if ! test_sync; then
        ((failures++))
    fi
    
    if ! test_key_integrity; then
        ((failures++))
    fi
    
    if [ $failures -eq 0 ]; then
        log "All sync tests PASSED"
        exit 0
    else
        error "$failures test(s) FAILED"
        exit 1
    fi
}

main "$@"
