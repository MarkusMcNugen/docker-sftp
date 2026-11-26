#!/bin/sh
# Run inside the server container by run-tests.sh: signs certificates with
# the file browser's authority for wan (web access, read-only) and nob (no
# web access), then tries them on the file browser's loopback sshd and on
# the public one. Prints one line per attempt: <attempt> ok|refused.
d=$(mktemp -d) || exit 2
cd "$d" || exit 2
ca=/config/sshd/keys/files_ca

try() {
    attempt=$1 who=$2 port=$3 commands=$4
    if printf '%s\n' "$commands" | sftp -b - -i "$who" -o CertificateFile="$who-cert.pub" -o IdentitiesOnly=yes \
        -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -P "$port" "$who@127.0.0.1" >/dev/null 2>&1; then
        echo "$attempt ok"
    else
        echo "$attempt refused"
    fi
}

for who in wan nob; do
    ssh-keygen -q -t ed25519 -N '' -C probe -f "$who" || exit 2
    ssh-keygen -q -s "$ca" -I probe -n "$who" -V +5m -O clear -O source-address=127.0.0.1 "$who.pub" || exit 2
done
try loopback-list wan 2299 'ls'
try loopback-upload wan 2299 'put /etc/hostname up/probe.txt'
try public-port wan 22 'ls'
try no-web-access nob 2299 'ls'
