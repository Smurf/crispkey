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

cleanup() {
    log "Cleaning up before test execution..."
    
    # Stop and remove containers
    podman stop crispkey-alice crispkey-bob 2>/dev/null || true
    podman rm crispkey-alice crispkey-bob 2>/dev/null || true
    
    # Clear volumes
    rm -rf "$PROJECT_DIR/test-volumes/alice/config"/* 2>/dev/null || true
    rm -rf "$PROJECT_DIR/test-volumes/bob/config"/* 2>/dev/null || true
    mkdir -p "$PROJECT_DIR/test-volumes/alice/config"
    mkdir -p "$PROJECT_DIR/test-volumes/bob/config"
    
    # Rebuild containers
    log "Rebuilding containers..."
    podman build -f "$PROJECT_DIR/Containerfile" -t crispkey:latest
    
    # Create and start containers
    podman-compose -f "$PROJECT_DIR/docker-compose.podman.yml" up -d
    sleep 3
    
    log "Cleanup and rebuild complete"
}

run_test() {
    local name=$1
    local script=$2
    
    log "=== Running $name ==="
    if "$SCRIPT_DIR/$script"; then
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
    
    # Cleanup before starting
    cleanup
    
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
}

main "$@"
