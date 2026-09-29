#!/bin/bash
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PQC_PYTHON:-python3}"
venv_dir="${PQC_VENV_DIR:-${HOME}/.local/share/pqc-discovery/venv}"
"$python_bin" -c 'import sys; sys.exit("Python 3.10 or newer is required" if sys.version_info < (3, 10) else 0)'
"$python_bin" -m venv "$venv_dir"
venv_dir="$(cd -- "$venv_dir" && pwd)"
"$venv_dir/bin/python" -m pip install --upgrade "$source_dir"
"$venv_dir/bin/pqc-discovery" doctor
printf '\nInstalled commands in %s/bin\nAdd this directory to PATH or invoke the commands by their full path.\n' "$venv_dir"
