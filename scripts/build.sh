#!/bin/bash
# scripts/build.sh - Build postkit distribution files

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Default: build all modules
MODULE="${1:-all}"

build_module() {
    local module="$1"
    local module_dir="$ROOT_DIR/$module"

    if [ ! -d "$module_dir/src" ]; then
        echo "Error: Module '$module' not found at $module_dir" >&2
        exit 1
    fi

    cat << HEADER
-- postkit/$module: Postgres-native ${module}
-- https://github.com/varunchopra/postkit
--
-- Install: psql \$DATABASE_URL -f ${module}.sql
-- License: Apache 2.0
--
-- Generated file - do not edit directly. See $module/src/ for source.

BEGIN;

HEADER

    # Schema (ordered)
    if [ -d "$module_dir/src/schema" ]; then
        echo "-- ============================================"
        echo "-- Schema"
        echo "-- ============================================"
        echo ""
        for f in "$module_dir"/src/schema/*.sql; do
            [ -f "$f" ] || continue
            echo "-- Source: $module/src/schema/$(basename "$f")"
            cat "$f"
            echo ""
        done
    fi

    # Functions (ordered)
    if [ -d "$module_dir/src/functions" ]; then
        echo "-- ============================================"
        echo "-- Functions"
        echo "-- ============================================"
        echo ""
        for f in "$module_dir"/src/functions/*.sql; do
            [ -f "$f" ] || continue
            echo "-- Source: $module/src/functions/$(basename "$f")"
            cat "$f"
            echo ""
        done
    fi

    # Triggers (ordered)
    if [ -d "$module_dir/src/triggers" ]; then
        echo "-- ============================================"
        echo "-- Triggers"
        echo "-- ============================================"
        echo ""
        for f in "$module_dir"/src/triggers/*.sql; do
            [ -f "$f" ] || continue
            echo "-- Source: $module/src/triggers/$(basename "$f")"
            cat "$f"
            echo ""
        done
    fi

    cat << FOOTER

COMMIT;

-- ============================================
-- Installation complete: $module
-- ============================================
FOOTER
}

build_all() {
    cat << HEADER
-- postkit: Postgres-native authentication, authorization, and organizations
-- https://github.com/varunchopra/postkit
--
-- Install: psql \$DATABASE_URL -f postkit.sql
-- License: Apache 2.0
--
-- Generated file - do not edit directly. See */src/ for source.

BEGIN;

HEADER

    # Build each module in order
    for module in authn authz config lease meter queue; do
        module_dir="$ROOT_DIR/$module"
        if [ -d "$module_dir/src" ] && [ "$(ls -A "$module_dir/src" 2>/dev/null)" ]; then
            echo ""
            echo "-- ============================================"
            echo "-- Module: $module"
            echo "-- ============================================"
            echo ""

            # Schema
            if [ -d "$module_dir/src/schema" ]; then
                for f in "$module_dir"/src/schema/*.sql; do
                    [ -f "$f" ] || continue
                    echo "-- Source: $module/src/schema/$(basename "$f")"
                    cat "$f"
                    echo ""
                done
            fi

            # Functions
            if [ -d "$module_dir/src/functions" ]; then
                for f in "$module_dir"/src/functions/*.sql; do
                    [ -f "$f" ] || continue
                    echo "-- Source: $module/src/functions/$(basename "$f")"
                    cat "$f"
                    echo ""
                done
            fi

            # Triggers
            if [ -d "$module_dir/src/triggers" ]; then
                for f in "$module_dir"/src/triggers/*.sql; do
                    [ -f "$f" ] || continue
                    echo "-- Source: $module/src/triggers/$(basename "$f")"
                    cat "$f"
                    echo ""
                done
            fi
        fi
    done

    cat << FOOTER

COMMIT;

-- ============================================
-- Installation complete
-- ============================================
--
-- Quick test:
--   SELECT authz.write('doc', '1', 'read', 'user', 'alice');
--   SELECT authz.check('user', 'alice', 'read', 'doc', '1');
--
FOOTER
}

case "$MODULE" in
    all)
        build_all
        ;;
    authn|authz|config|lease|meter|queue)
        build_module "$MODULE"
        ;;
    *)
        echo "Usage: $0 [all|authn|authz|config|lease|meter|queue]" >&2
        exit 1
        ;;
esac
