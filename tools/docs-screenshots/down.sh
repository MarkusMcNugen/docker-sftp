#!/usr/bin/env bash
# Removes the demo server up.sh started: the sftp-shots containers and
# network, and the files in SHOTS_DATA, by default ~/.local/share/sftp-shots.
# The image is left alone. Usage: bash down.sh
set -u
base=${SHOTS_DATA:-$HOME/.local/share/sftp-shots}
podman rm -f --ignore sftp-shots sftp-shots-idle >/dev/null && echo "containers removed"
if podman network exists sftp-shots; then podman network rm sftp-shots >/dev/null && echo "network removed"; fi
if [ -d "$base" ]; then podman unshare rm -rf "$base" && echo "removed $base"; fi
