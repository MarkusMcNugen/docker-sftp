#!/usr/bin/env bash
# Fails one password login to sftp-shots under each name given, as a
# password guesser does, from this client container's address. Five names
# reach fail2ban's maxretry, so the last one bans the address.
# Usage: bash /client/attack.sh name...
set -u
printf '#!/bin/sh\necho wrong-password\n' >/tmp/askpass
chmod 700 /tmp/askpass
for name in "$@"; do
    SSH_ASKPASS=/tmp/askpass SSH_ASKPASS_REQUIRE=force ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \
        "$name@sftp-shots" true </dev/null
done
echo "ATTACK DONE"
