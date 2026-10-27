#!/bin/sh
set -eu
exec /usr/bin/python3 -Es -B "$(dirname -- "$0")/setup_runner.py" "$@"
