#!/bin/bash
# test-sync.sh - Test encrypted vault synchronization between containers
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

get_device_id() {
    local container=$1
    exec_in "$container" cat /home/testuser/.config/crispkey/device_id 2>/dev/null || echo ""
}

get_alice_ip() {
    podman inspect "$ALICE" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

count_vaults() {
    local container=$1
    local count
    count=$(exec_in "$container" sh -c 'ls /home/testuser/.config/crispkey/vaults/*.vault 2>/dev/null | wc -l' | tr -d ' ')
    echo "$count"
}

count_gpg_keys() {
    local container=$1
    local output
    output=$(exec_in "$container" gpg --list-keys --with-colons 2>/dev/null)
    echo "$output" | grep -c "^pub" || echo "0"
}

get_alice_vault_fps() {
    exec_in "$ALICE" sh -c 'ls /home/testuser/.config/crispkey/vaults/*.vault 2>/dev/null' | xargs -I{} basename {} .vault | sort || true
}

unlock_vaults() {
    local container=$1
    exec_in "$container" expect -c "
        spawn crispkey unlock
        expect \"master password\"
        send \"$MASTER_PASSWORD\r\"
        expect eof
    " 2>/dev/null || true
}

test_sync() {
    log "Testing vault sync..."
    
    local alice_id
    alice_id=$(get_device_id "$ALICE")
    
    if [ -z "$alice_id" ]; then
        error "Could not get Alice's device ID"
        return 1
    fi
    
    log "Alice device ID: $alice_id"
    
    local alice_vaults_before bob_vaults_before
    alice_vaults_before=$(count_vaults "$ALICE")
    bob_vaults_before=$(count_vaults "$BOB")
    
    log "Vaults before sync - Alice: $alice_vaults_before, Bob: $bob_vaults_before"
    
    if [ "$alice_vaults_before" -eq 0 ]; then
        error "Alice has no vaults to sync"
        return 1
    fi
    
    local alice_ip
    alice_ip=$(get_alice_ip)
    
    log "Alice IP: $alice_ip"
    
    log "Pairing Bob with Alice..."
    exec_in "$BOB" crispkey pair "$alice_ip" 2>&1 || true
    
    log "Unlocking Alice's vaults..."
    unlock_vaults "$ALICE"
    
    log "Unlocking Bob's vaults..."
    unlock_vaults "$BOB"
    
    log "Running sync from Bob (pulling from Alice)..."
    local sync_output
    sync_output=$(exec_in "$BOB" expect -c "
        spawn crispkey sync $alice_id
        expect \"sync password\"
        send \"$SYNC_PASSWORD\r\"
        expect eof
    " 2>&1 || true)
    
    log "Sync output: $sync_output"
    
    sleep 1
    local bob_vaults_after
    bob_vaults_after=$(count_vaults "$BOB")
    
    log "Vaults after sync - Bob: $bob_vaults_after"
    
    if [ "$bob_vaults_after" -ge "$alice_vaults_before" ]; then
        log "Sync: PASS - Vaults transferred to Bob"
        return 0
    else
        error "Sync: FAIL - Vaults not transferred (expected >= $alice_vaults_before, got $bob_vaults_after)"
        return 1
    fi
}

test_vault_integrity() {
    log "Testing vault integrity..."
    
    local alice_fps bob_fps
    alice_fps=$(get_alice_vault_fps)
    bob_fps=$(exec_in "$BOB" sh -c 'ls /home/testuser/.config/crispkey/vaults/*.vault 2>/dev/null' | xargs -I{} basename {} .vault | sort || true)
    
    if [ -z "$alice_fps" ]; then
        error "No vaults found in Alice"
        return 1
    fi
    
    log "Alice vault fingerprints:"
    echo "$alice_fps" | while read fp; do
        [ -n "$fp" ] && log "  $fp"
    done
    
    log "Bob vault fingerprints:"
    echo "$bob_fps" | while read fp; do
        [ -n "$fp" ] && log "  $fp"
    done
    
    local all_found=true
    while read fp; do
        if [ -n "$fp" ] && ! echo "$bob_fps" | grep -q "$fp"; then
            error "Vault $fp not found in Bob"
            all_found=false
        fi
    done <<< "$alice_fps"
    
    if [ "$all_found" = true ]; then
        log "Integrity: PASS - All vaults match"
        return 0
    else
        error "Integrity: FAIL - Vault mismatch"
        return 1
    fi
}

test_vault_decryption() {
    log "Testing vault decryption..."
    
    unlock_vaults "$BOB"
    
    local vault_list
    vault_list=$(exec_in "$BOB" crispkey vault list 2>&1 || true)
    
    log "Bob's vaults:"
    echo "$vault_list" | while read line; do
        log "  $line"
    done
    
    if echo "$vault_list" | grep -q "Size:"; then
        log "Decryption: PASS - Vaults can be listed"
        return 0
    else
        error "Decryption: FAIL - Cannot list vaults"
        return 1
    fi
}

main() {
    log "Starting vault sync tests..."
    echo $1
    if [ $1 != "NOBUILD" ]
    then
      "$SCRIPT_DIR/rebuild-containers.sh"
    fi
    
    local failures=0
    
    if ! test_sync; then
        ((failures++))
    fi
    
    if ! test_vault_integrity; then
        ((failures++))
    fi
    
    if ! test_vault_decryption; then
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
