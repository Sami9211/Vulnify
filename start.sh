#!/usr/bin/env bash
# Backwards-compatible entry point — delegates to the robust cross-platform
# launcher. Use ./run.sh directly for new setups (or run.bat on Windows).
exec "$(cd "$(dirname "$0")" && pwd)/run.sh" "$@"
