#!/bin/bash
# BPF Resource Thief Detector — launcher
#
# eBPF requires root, but running under sudo changes $HOME to /root.  Python
# derives its per-user site-packages directory from $HOME, so as root it looks
# in /root/.local/... and every package installed with `pip install --user`
# (torch, scikit-learn, ...) becomes invisible — which silently disables the
# LSTM model.  Passing PYTHONPATH explicitly keeps those packages reachable.

PROJECT="/home/sudipto-roy-s-hawon/Downloads/Project"
VENV="$PROJECT/venv/bin/python3"
SCRIPT="$PROJECT/src/dashboard.py"

# Per-user site-packages of the *invoking* user, resolved before sudo runs
USER_SITE="$HOME/.local/lib/python3.14/site-packages"

if [ ! -x "$VENV" ]; then
    echo "ERROR: venv python not found at $VENV"
    exit 1
fi

sudo PYTHONPATH="$USER_SITE" "$VENV" "$SCRIPT"
