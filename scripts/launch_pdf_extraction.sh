#!/bin/sh
# Explicit job arguments are passed by the generated offline desktop launcher.
set -eu
launcher_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$launcher_root"
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
launcher_status=0
if [ ! -x "$launcher_root/.venv/bin/python" ]; then
    echo 'CHUA CHAY: thieu .venv/bin/python; khong tai dependency tu dong.'
    launcher_status=1
elif "$launcher_root/.venv/bin/python" -I "$launcher_root/scripts/24_launch_pdf_extraction.py" "$@"; then
    launcher_status=0
else
    launcher_status=$?
fi
if [ -t 0 ] && [ -t 1 ]; then
    printf '\nNhan Enter de dong cua so: '
    IFS= read -r launcher_reply || :
fi
exit "$launcher_status"
