#!/usr/bin/env bash
# Makes the demo accounts' activity over sftp from a client container on the
# sftp-shots network: alice and carol upload with passwords, erin lists her
# folder, and bob downloads with his key. Usage: bash /client/activity.sh
set -u
opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
work=$(mktemp -d)

# Runs the sftp commands in file $3 as account $1, with password $2.
with_password() {
    printf '#!/bin/sh\necho %s\n' "$2" >"$work/askpass"
    chmod 700 "$work/askpass"
    SSH_ASKPASS="$work/askpass" SSH_ASKPASS_REQUIRE=force sftp "${opts[@]}" "$1@sftp-shots" <"$3"
}

cd /client/files/alice || exit 1
printf '%s\n' "mkdir upload/projects" "put quarterly-report.pdf upload/" "put meeting-notes.txt upload/" \
    "put site-photos.zip upload/" "put site-backup.tar.gz upload/" "put harbor.png photos/" "put garden.png photos/" \
    "rename upload/meeting-notes.txt upload/projects/meeting-notes.txt" >"$work/alice"
with_password alice Garden-Path-4417 "$work/alice"

cd /client/files/carol || exit 1
printf '%s\n' "put monthly-summary.pdf reports/" >"$work/carol"
with_password carol Harbor-Light-2290 "$work/carol"

printf '%s\n' "ls upload" >"$work/erin"
with_password erin Copper-Lake-6153 "$work/erin"

cd "$work" || exit 1
printf '%s\n' "get inbox/contract-draft.pdf" "get inbox/price-list.csv" >"$work/bob"
sftp "${opts[@]}" -i /client/bob_key bob@sftp-shots <"$work/bob"
echo "ACTIVITY DONE"
