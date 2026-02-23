#!/bin/bash
# iterative-test.sh - Watch for code changes and run tests
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

build_and_deploy() {
    log "Building crispkey..."
    
    cd "$PROJECT_DIR"
    
    # Build escript
    if mix escript.build; then
        log "Build successful"
    else
        error "Build failed"
        return 1
    fi
    
    # Copy to containers
    log "Deploying to containers..."
    
    podman cp "$PROJECT_DIR/crispkey" "$ALICE":/usr/local/bin/crispkey
    podman cp "$PROJECT_DIR/crispkey" "$BOB":/usr/local/bin/crispkey
    
    # Restart containers
    log "Restarting containers..."
    podman restart "$ALICE" "$BOB"
    
    # Wait for containers to be ready
    sleep 3
    
    return 0
}

run_tests() {
    log "Running tests..."
    
    if "$SCRIPT_DIR/test-all.sh"; then
        log "Tests PASSED"
        return 0
    else
        error "Tests FAILED"
        return 1
    fi
}

check_dependencies() {
    # Check for inotifywait or fswatch
    if command -v inotifywait &> /dev/null; then
        WATCHER="inotify"
    elif command -v fswatch &> /dev/null; then
        WATCHER="fswatch"
    else
        error "No file watcher found. Install inotify-tools or fswatch."
        exit 1
    fi
    
    # Check for podman
    if ! command -v podman &> /dev/null; then
        error "podman not found"
        exit 1
    fi
    
    # Check for mix
    if ! command -v mix &> /dev/null; then
        error "mix not found (Elixir required)"
        exit 1
    fi
}

watch_inotify() {
    log "Watching for changes (inotify)..."
    
    inotifywait -m -r -e modify,create,delete \
        "$PROJECT_DIR/lib" \
        "$PROJECT_DIR/config" \
        --exclude '\.#|\.sw[px]$|~$' | \
    while read path action file; do
        log "Change detected: $path$file ($action)"
        build_and_deploy && run_tests
    done
}

watch_fswatch() {
    log "Watching for changes (fswatch)..."
    
    fswatch -r --exclude "\\.sw[px]$" --exclude "~$" \
        "$PROJECT_DIR/lib" \
        "$PROJECT_DIR/config" | \
    while read path; do
        log "Change detected: $path"
        build_and_deploy && run_tests
    done
}

initial_run() {
    log "Running initial build and test..."
    build_and_deploy && run_tests
}

main() {
    log "Crispkey Iterative Testing"
    log "=========================="
    
    check_dependencies
    
    # Initial run
    initial_run
    
    # Watch for changes
    case $WATCHER in
        inotify)
            watch_inotify
            ;;
        fswatch)
            watch_fswatch
            ;;
    esac
}

main "$@"
