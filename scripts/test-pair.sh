#!/bin/bash
# test-pair.sh - Test discovery and pairing between containers
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

ALICE="crispkey-alice"
BOB="crispkey-bob"

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
    # Get Bob's IP on the test network
    podman inspect "$BOB" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

test_discovery() {
    log "Testing discovery from Alice..."
    
    # Run discovery from Alice, look for Bob
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

test_pairing() {
    log "Testing pairing..."
    
    local bob_id
    bob_id=$(get_device_id "$BOB")
    
    if [ -z "$bob_id" ]; then
        error "Could not get Bob's device ID"
        return 1
    fi
    
    log "Bob's device ID: $bob_id"
    
    # Pair from Alice to Bob (by IP since we know it)
    local bob_ip
    bob_ip=$(get_bob_ip)
    
    if [ -z "$bob_ip" ]; then
        error "Could not get Bob's IP address"
        return 1
    fi
    
    log "Bob's IP: $bob_ip"
    
    # Pair Alice -> Bob
    log "Pairing Alice -> Bob..."
    local pair_output
    pair_output=$(exec_in "$ALICE" crispkey pair "$bob_ip" 2>&1 || true)
    
    log "Pair output: $pair_output"
    
    # Verify pairing in Alice's state
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
