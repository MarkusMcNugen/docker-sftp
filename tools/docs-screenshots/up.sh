#!/usr/bin/env bash
# Starts sftp-shots, a demo server for the documentation's screenshots, from
# IMAGE with the demo accounts beside this script, on the podman network
# sftp-shots, publishing sftp, the admin web UI and the file browser on 2222,
# 8443 and 8444; then makes the demo activity and three password guessers'
# failed logins, seeds a week of history before them, and prints the first
# admin's setup token. Its files go in SHOTS_DATA, by default
# ~/.local/share/sftp-shots. Usage: bash up.sh IMAGE
set -u
image=${1:?image}
base=${SHOTS_DATA:-$HOME/.local/share/sftp-shots}
src=$(cd "$(dirname "$0")" && pwd)
client() { podman run --rm --network sftp-shots --entrypoint bash -v "$base/client:/client:ro" "$image" "$@"; }

podman rm -f --ignore sftp-shots sftp-shots-idle >/dev/null
podman network exists sftp-shots || podman network create sftp-shots >/dev/null
if [ -d "$base" ]; then podman unshare rm -rf "$base"; fi
mkdir -p "$base/config/sshd" "$base/config/userkeys" "$base/client"
cp "$src/users.conf" "$src/groups.conf" "$src/settings.conf" "$base/config/sshd/"
cp "$src/activity.sh" "$src/attack.sh" "$base/client/"
python3 "$src/make-files.py" "$base/client/files"
ssh-keygen -q -t ed25519 -N '' -C bob@laptop -f "$base/client/bob_key"
cp "$base/client/bob_key.pub" "$base/config/userkeys/bob.pub"
podman image exists "$image" || podman pull -q "$image" >/dev/null || { echo "UP FAILED: pull"; exit 1; }
podman run -d --name sftp-shots --network sftp-shots --cap-add NET_ADMIN --cap-add NET_RAW \
    -p 2222:22 -p 8443:8443 -p 8444:8444 \
    -e WEBUI_ENABLED=true -e WEBUI_FILES_ENABLED=true -e WEBUI_TRUSTED_PROXIES="10.0.0.0/8 127.0.0.0/8 192.168.0.0/16" \
    -v "$base/config:/config" "$image" >/dev/null || { echo "UP FAILED: run"; exit 1; }
until podman logs sftp-shots 2>&1 | grep -q 'setup?token='; do
    if [ "$(podman inspect -f '{{.State.Running}}' sftp-shots)" != true ]; then
        echo "UP FAILED: the container stopped"
        podman logs sftp-shots 2>&1 | tail -n 30
        exit 1
    fi
    sleep 2
done
for f in contract-draft.pdf price-list.csv; do podman cp "$base/client/files/bob/$f" "sftp-shots:/home/bob/inbox/$f"; done
podman exec sftp-shots chown -R 1002:100 /home/bob/inbox
client /client/activity.sh
client /client/attack.sh admin root test oracle ubuntu
client /client/attack.sh git postgres deploy user pi
client /client/attack.sh alice alice alice alice alice alice
podman cp "$src/seed-history.py" sftp-shots:/tmp/seed-history.py
podman exec sftp-shots python3 /tmp/seed-history.py
podman run -d --rm --name sftp-shots-idle --network sftp-shots --entrypoint bash -v "$base/client:/client:ro" "$image" \
    -c 'sleep 3600 | sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /client/bob_key bob@sftp-shots' >/dev/null
echo "SETUP $(podman logs sftp-shots 2>&1 | grep -o 'setup?token=[^ ]*' | tail -n 1)"
echo "UP DONE"
