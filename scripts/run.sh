#!/usr/bin/env bash
# Run the plugin with its dedicated Linux/WSL dependencies.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
TOOLS_DIR="$(cd -- "$REPO_DIR/../ghidra_tools" && pwd)"

export GHIDRA_INSTALL_DIR="$TOOLS_DIR/ghidra_12.2_PUBLIC"
export JAVA_HOME="$TOOLS_DIR/jdk-25"
export VIRTUAL_ENV="$TOOLS_DIR/python_env"
# Prefer the system GCC over an unrelated Conda compiler.
export PATH="$VIRTUAL_ENV/bin:$JAVA_HOME/bin:/usr/bin:/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
export XDG_CONFIG_HOME="$TOOLS_DIR/runtime/config"
export XDG_CACHE_HOME="$TOOLS_DIR/runtime/cache"
mkdir -p -- "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
if [[ -d "$TOOLS_DIR/qt_libs/usr/lib/x86_64-linux-gnu" ]]; then
    export LD_LIBRARY_PATH="$TOOLS_DIR/qt_libs/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

for tool in "$VIRTUAL_ENV/bin/python" "$JAVA_HOME/bin/java" "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"; do
    if [[ ! -x "$tool" ]]; then
        printf 'Missing runtime component: %s\n' "$tool" >&2
        exit 1
    fi
done

cd -- "$REPO_DIR"
if [[ $# -eq 0 ]]; then
    exec "$VIRTUAL_ENV/bin/python" plugins/decompile_gui.py
fi
exec "$@"
