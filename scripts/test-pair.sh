#!/bin/bash
# test-pair.sh - Test discovery and pairing between containers
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

ALICE="crispkey-alice"
BOB="crispkey-bob"
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

get_bob_ip() {
    podman inspect "$BOB" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

test_discovery() {
    log "Testing discovery from Alice..."
    
    local output
    output=$(exec_in "$ALICE" crispkey discover 3 2>&1 || true)
    
    log "Discovery output: $output"
    
    if echo "$output" | grep -q "Found"; then
        log "Discovery: PASS - Found devices"
        return 0
    else
        error "Discovery: FAIL - No devices found"
        return 1
    fi
}

get_alice_ip() {
    podman inspect "$ALICE" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

test_pairing() {
    log "Testing pairing..."
    
    local alice_id bob_id
    alice_id=$(get_device_id "$ALICE")
    bob_id=$(get_device_id "$BOB")
    
    if [ -z "$bob_id" ]; then
        error "Could not get Bob's device ID"
        return 1
    fi
    
    if [ -z "$alice_id" ]; then
        error "Could not get Alice's device ID"
        return 1
    fi
    
    log "Alice's device ID: $alice_id"
    log "Bob's device ID: $bob_id"
    
    local alice_ip
    alice_ip=$(get_alice_ip)
    
    if [ -z "$alice_ip" ]; then
        error "Could not get Alice's IP address"
        return 1
    fi
    
    log "Alice's IP: $alice_ip"
    
    log "Pairing Bob with Alice..."
    local pair_output
    pair_output=$(exec_in "$BOB" crispkey pair "$alice_ip" 2>&1 || true)
    
    log "Pair output: $pair_output"
    
    sleep 1
    
    local peers
    peers=$(exec_in "$ALICE" crispkey devices 2>&1 || true)
    
    log "Alice's paired devices: $peers"
    
    if echo "$peers" | grep -q "$bob_id"; then
        log "Pairing: PASS - Bob is paired with Alice"
        return 0
    else
        error "Pairing: FAIL - Bob not found in Alice's paired devices"
        return 1
    fi
}

main() {
    log "Starting pairing tests..."
    
    if [ $1 != "NOBUILD"]
    then
      "$SCRIPT_DIR/rebuild-containers.sh"
    fi
    
    local failures=0
    
    if ! test_discovery; then
        ((failures++))
    fi
    
    if ! test_pairing; then
        ((failures++))
    fi
    
    if [ $failures -eq 0 ]; then
        log "All pairing tests PASSED"
        exit 0
    else
        error "$failures test(s) FAILED"
        exit 1
    fi
}

main "$@"
