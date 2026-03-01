#!/bin/bash
# test-all.sh - Run full test suite
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

error() {
    echo "[$(date '+%H:%M:%S')] ERROR: $1" >&2
}

run_test() {
    local name=$1
    local script=$2
    
    log "=== Running $name ==="
    if "$SCRIPT_DIR/$script" NOBUILD; then
        log "=== $name: PASSED ==="
        return 0
    else
        error "=== $name: FAILED ==="
        return 1
    fi
}
main() {
    log "Starting full test suite..."
    log "======================================"
    $SCRIPT_DIR/rebuild-containers.sh
    local failures=0
    
    if ! run_test "Setup" "test-setup.sh"; then
        ((failures++))
    fi
    
    if ! run_test "Pairing" "test-pair.sh"; then
        ((failures++))
    fi
    
    if ! run_test "Sync" "test-sync.sh"; then
        ((failures++))
    fi
    
    log "======================================"
    
    if [ $failures -eq 0 ]; then
        log "All tests PASSED!"
        exit 0
    else
        error "$failures test suite(s) FAILED"
        exit 1
    fi
    podman-compose -f docker-compose.podman.yml down
}

main "$@"
