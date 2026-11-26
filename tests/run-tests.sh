#!/usr/bin/env bash
# Integration tests for the SFTP image. Every check drives a running server
# container with a real OpenSSH client from a second container.
#
#   tests/run-tests.sh [image]
#   SCENARIOS="main options" tests/run-tests.sh [image]
#
# Without an image argument, the image is built from the repository first.
# ENGINE picks the container engine (default: docker, else podman). The
# engine must be able to grant NET_ADMIN so that fail2ban can ban.
# SCENARIOS picks which scenarios run (default: all of them, in order).
# Exits non-zero when any check fails.
#
# Checks are single-quoted strings handed to eval, so they expand after
# capture has filled OUT and RC.
# shellcheck disable=SC2016

set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

ENGINE=${ENGINE:-$(command -v docker || command -v podman)}
IMAGE=${1:-}
RUN_ID=sftp-test-$$
NET=$RUN_ID-net
# TEST-NET-2, which belongs to no country and to no private range.
FARNET=$RUN_ID-farnet
CLIENT=$RUN_ID-client
ATTACKER=$RUN_ID-attacker
WORK=$(mktemp -d)
FIXTURES=$PWD/tests/fixtures
ALL_SCENARIOS=(main crash hardened port options rotation rsync perms groups countries browser apply webui legacy reject)
PASSED=0
FAILED=0
SKIPPED=0
FAILURES=()
OUT=""
RC=0
SERVER=""
SERVER_IP=""

engine() { "$ENGINE" "$@"; }

die() {
    printf 'setup failed: %s\n' "$*" >&2
    exit 2
}

pass() {
    PASSED=$((PASSED + 1))
    printf 'ok      %s\n' "$1"
}

fail() {
    FAILED=$((FAILED + 1))
    FAILURES+=("$1")
    printf 'not ok  %s\n' "$1"
    # The end of the output, where an error says what failed.
    if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/        | /' | tail -20; fi
}

skip() {
    SKIPPED=$((SKIPPED + 1))
    printf 'skip    %s (%s)\n' "$1" "$2"
}

# capture <command...>: runs the command, keeping its combined output in
# OUT and its exit status in RC.
capture() {
    OUT=$("$@" 2>&1) && RC=0 || RC=$?
}

expect() {
    local name=$1
    shift
    if "$@"; then pass "$name"; else fail "$name" "$OUT"; fi
}

has() { grep -qF -- "$1" <<<"$OUT"; }
lacks() { ! grep -qF -- "$1" <<<"$OUT"; }

cleanup() {
    local -a ids=()
    mapfile -t ids < <(engine ps -aq --filter "name=$RUN_ID")
    ((${#ids[@]})) && engine rm -f "${ids[@]}" >/dev/null 2>&1
    engine network rm "$NET" >/dev/null 2>&1
    engine network rm "$FARNET" >/dev/null 2>&1
    # Containers write into $WORK as their root user, which on Docker is the
    # host's root, so the tree is emptied from inside a container.
    engine run --rm -v "$WORK:/w" "$IMAGE" find /w -mindepth 1 -delete >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

ip_of() {
    engine inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

# start_server <name> <config dir> [engine run options...] [-- image args...]
start_server() {
    local name=$1 cfg=$2
    shift 2
    local -a opts=() args=()
    while (($#)) && [[ $1 != -- ]]; do opts+=("$1"); shift; done
    (($#)) && shift
    args=("$@")
    engine run -d --name "$name" --network "$NET" --cap-add NET_ADMIN --cap-add NET_RAW \
        -v "$cfg:/config" "${opts[@]}" "$IMAGE" "${args[@]}" >/dev/null
}

wait_healthy() {
    local name=$1 tries=60
    until engine exec "$name" /usr/local/bin/healthcheck >/dev/null 2>&1; do
        [[ $(engine inspect -f '{{.State.Running}}' "$name") == true ]] || return 1
        ((--tries)) || return 1
        sleep 1
    done
}

server_log_tail() { engine logs "$SERVER" 2>&1 | tail -30; }

# trust_host <name> <config dir> [port]: pins the server's ed25519 host key.
trust_host() {
    local ip key port=${3:-22}
    ip=$(ip_of "$1")
    key=$(cat "$2/sshd/keys/ssh_host_ed25519_key.pub") || die "no host key in $2"
    if [[ $port == 22 ]]; then
        printf '%s %s\n' "$ip" "$key" >"$WORK/client/known_hosts"
    else
        printf '[%s]:%s %s\n' "$ip" "$port" "$key" >"$WORK/client/known_hosts"
    fi
    SERVER_IP=$ip
}

SSH_OPTS=(-o UserKnownHostsFile=/client/known_hosts -o StrictHostKeyChecking=yes
    -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 -o LogLevel=ERROR)

# ssh keeps the first value it reads for an option, so per-call options
# come before SSH_OPTS in every helper below.

# sftp_password <from> <user> <password> <commands> [ssh options...]
sftp_password() {
    local from=$1 user=$2 pw=$3 cmds=$4
    shift 4
    printf '%s\n' "$cmds" | engine exec -i -e SSH_ASKPASS=/client/askpass -e SSH_ASKPASS_REQUIRE=force \
        -e TEST_PASSWORD="$pw" "$from" sftp "$@" "${SSH_OPTS[@]}" -o PubkeyAuthentication=no "$user@$SERVER_IP"
}

# sftp_key <from> <user> <key> <commands> [ssh options...]: -b makes a
# failed command fail the session.
sftp_key() {
    local from=$1 user=$2 key=$3 cmds=$4
    shift 4
    printf '%s\n' "$cmds" | engine exec -i "$from" sftp -b - "$@" "${SSH_OPTS[@]}" -o PasswordAuthentication=no \
        -o IdentitiesOnly=yes -i "/client/$key" "$user@$SERVER_IP"
}

# ssh_password <from> <user> <password> "<remote command>" [ssh options...]
# The remote command follows the destination, as ssh's argument order
# requires; an empty one requests no command.
ssh_password() {
    local from=$1 user=$2 pw=$3
    local -a remote=()
    read -r -a remote <<<"$4"
    shift 4
    engine exec -e SSH_ASKPASS=/client/askpass -e SSH_ASKPASS_REQUIRE=force -e TEST_PASSWORD="$pw" "$from" \
        timeout 20 ssh "$@" "${SSH_OPTS[@]}" -o PubkeyAuthentication=no -l "$user" "$SERVER_IP" "${remote[@]}"
}

# rsync_password <from> <user> <password> <rsync arguments...>
rsync_password() {
    local from=$1 user=$2 pw=$3
    shift 3
    engine exec -e SSH_ASKPASS=/client/askpass -e SSH_ASKPASS_REQUIRE=force -e TEST_PASSWORD="$pw" "$from" \
        timeout 30 rsync -e "ssh ${SSH_OPTS[*]} -o PubkeyAuthentication=no -l $user" "$@"
}

# negotiate [ssh options...]: a connection that stops at authentication.
# ssh reports a failed negotiation at LogLevel=INFO, which SSH_OPTS hides.
negotiate() {
    engine exec "$CLIENT" ssh -o LogLevel=INFO -o BatchMode=yes "$@" "${SSH_OPTS[@]}" "nobody@$SERVER_IP" true
}

in_server() { engine exec "$SERVER" "$@"; }

# The server's process titles, one per line. The image has no ps.
process_titles() {
    in_server sh -c 'for p in /proc/[0-9]*; do tr "\0" " " <"$p/cmdline" 2>/dev/null; echo; done'
}

# has_session <account>: true while the account has an open SSH session.
# The titles are read in full before grep: under pipefail, grep -q leaving
# early would fail the pipeline when the exec writing into it gets SIGPIPE.
has_session() {
    local titles
    titles=$(process_titles) || return 1
    grep -q "^sshd-session: $1 \[priv\]" <<<"$titles"
}

# True when a host profile attached itself to rsyslogd: its security label
# differs from process 1's. Under Docker every process shares one label.
rsyslog_confined_by_host() {
    local labels
    labels=$(in_server sh -c 'cat /proc/1/attr/current; for p in /proc/[0-9]*; do [ "$(cat $p/comm)" = rsyslogd ] && cat $p/attr/current; done' 2>/dev/null)
    [[ $(sort -u <<<"$labels" | wc -l) -gt 1 ]]
}

# ---------------------------------------------------------------------------
# Four users, transfer logging, drop-ins, a fail2ban override, bans, and
# reconciliation across a restart. users.conf and the key use CRLF line
# endings, as files edited on Windows do.
# ---------------------------------------------------------------------------
scenario_main() {
    local main=$WORK/main/config
    mkdir -p "$main/sshd/sshd_config.d" "$main/userkeys" "$main/fail2ban" "$main/sshd/scripts"
    printf '%s\r\n' "# test accounts" \
        "alice:alice-pw-1:1001:100:upload" \
        "bob::1002:100:data/inbox" \
        "carol:$CAROL_HASH:e:1003::docs" \
        "dave:dave-pw-1:1004" >"$main/sshd/users.conf"
    sed 's/$/\r/' "$WORK/client/bob_key.pub" >"$main/userkeys/bob.pub"
    printf 'PerSourcePenaltyExemptList %s\n' "$CLIENT_IP" >"$main/sshd/sshd_config.d/10-test.conf"
    printf '[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 %s\n' "$CLIENT_IP" >"$main/fail2ban/jail.local"
    printf 'touch /run/sftp/custom-script-ran\n' >"$main/sshd/scripts/10-marker.sh"

    SERVER=$RUN_ID-main
    start_server "$SERVER" "$main" -e SFTP_LOG_TRANSFERS=true || die "main server did not start"
    if wait_healthy "$SERVER"; then pass "main server becomes healthy"; else
        fail "main server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$main"

    capture engine logs "$SERVER"
    expect "passwords never appear in the log" lacks "alice-pw-1"
    expect "custom .sh script runs without the executable bit" in_server test -e /run/sftp/custom-script-ran
    capture stat -c %a "$main/sshd/keys/ssh_host_ed25519_key"
    expect "generated host key is mode 600" [ "$OUT" = 600 ]
    capture in_server stat -c '%a %n' /etc/ssh /etc/fail2ban /etc/fail2ban/jail.d /usr/local/bin /usr/local/libexec/sftp
    expect "the image's own directories are mode 755, whatever the build context's modes" eval '! grep -qv "^755 " <<<"$OUT"'
    capture in_server /usr/sbin/sshd -T
    expect "sshd_config.d drop-in is applied" has "persourcepenaltyexemptlist $CLIENT_IP"

    capture sftp_password "$CLIENT" alice alice-pw-1 "put /client/hello.txt upload/hello.txt"
    capture in_server stat -c %u:%g /home/alice/upload/hello.txt
    expect "alice uploads with a password; file is owned 1001:100" [ "$OUT" = 1001:100 ]

    capture sftp_password "$CLIENT" alice alice-pw-1 $'pwd\nls -1 /\nget /etc/passwd /tmp/stolen'
    expect "alice is jailed in her home directory" \
        eval 'has "Remote working directory: /" && has "upload" && ! engine exec "$CLIENT" test -e /tmp/stolen'
    capture sftp_password "$CLIENT" alice alice-pw-1 "put /client/hello.txt /at-root.txt"
    expect "alice cannot write to the root of her jail" eval '! in_server test -e /home/alice/at-root.txt'

    capture sftp_password "$CLIENT" alice wrong-password "pwd"
    expect "a wrong password is refused" eval '((RC != 0)) && has "Permission denied"'

    capture sftp_key "$CLIENT" bob bob_key "put /client/hello.txt data/inbox/hello.txt"
    expect "bob logs in with a CRLF-mangled key file" [ "$RC" = 0 ]
    capture in_server stat -c %u:%g /home/bob/data /home/bob/data/inbox /home/bob/data/inbox/hello.txt
    expect "every created component of data/inbox is owned by bob" [ "$OUT" = $'1002:100\n1002:100\n1002:100' ]
    capture sftp_password "$CLIENT" bob "" "pwd"
    expect "bob has no password login" eval '((RC != 0)) && has "Permission denied"'
    capture sftp_key "$CLIENT" bob stranger_key "pwd"
    expect "an unlisted key is refused" eval '((RC != 0)) && has "Permission denied"'

    capture sftp_password "$CLIENT" carol carol-pw-1 "ls"
    expect "carol logs in with a yescrypt hash" eval '((RC == 0)) && lacks "Permission denied"'
    capture in_server id -g dave
    expect "a user without a gid gets group 100" [ "$OUT" = 100 ]

    capture ssh_password "$CLIENT" alice alice-pw-1 id
    expect "shell commands are refused" eval 'has "This service allows sftp connections only." && lacks "uid="'
    capture ssh_password "$CLIENT" alice alice-pw-1 "" -N -o ExitOnForwardFailure=yes -R 2022:127.0.0.1:22
    expect "port forwarding is refused" eval '((RC != 0)) && has "forwarding failed"'

    capture negotiate -o KexAlgorithms=diffie-hellman-group14-sha1
    expect "SHA-1 key exchange is refused" has "no matching key exchange method"
    capture negotiate -o Ciphers=aes128-cbc
    expect "CBC ciphers are refused" has "no matching cipher"
    capture negotiate -o Ciphers=aes128-ctr -o MACs=hmac-sha1
    expect "SHA-1 MACs are refused" has "no matching MAC"
    capture negotiate -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256
    expect "the modern policy accepts plain hmac-sha2-256" eval 'has "Permission denied" && lacks "no matching"'
    capture negotiate -v
    expect "post-quantum mlkem768x25519 key exchange is negotiated" has "kex: algorithm: mlkem768x25519-sha256"

    capture engine logs "$SERVER"
    if ! has "did not create /home/alice/dev/log"; then
        expect "transfers are logged" has 'open "/upload/hello.txt"'
    elif rsyslog_confined_by_host; then
        skip "transfers are logged" "a host security policy confines rsyslogd; the entrypoint warned as designed"
    else
        fail "the chroot log socket is missing although no host policy confines rsyslogd" "$OUT"
    fi

    # Two sessions of three wrong passwords from the attacker.
    local _ banned=false
    for _ in 1 2; do
        ssh_password "$ATTACKER" alice not-the-password true -o NumberOfPasswordPrompts=3 >/dev/null 2>&1
    done
    for _ in $(seq 20); do
        capture in_server fail2ban-client get sshd banip
        if has "$ATTACKER_IP"; then banned=true; break; fi
        sleep 1
    done
    expect "fail2ban bans a brute-force source" $banned
    capture ssh_password "$ATTACKER" alice alice-pw-1 true
    expect "the ban blocks even the right password" eval 'has "refused" || has "timed out"'
    capture sftp_password "$CLIENT" alice alice-pw-1 "pwd"
    expect "other sources are unaffected by the ban" eval '((RC == 0))'

    # Reconcile on restart: dave removed, alice's password changed, bob's key revoked.
    printf '%s\n' "alice:alice-pw-2:1001:100:upload" "bob::1002:100:data/inbox" \
        "carol:$CAROL_HASH:e:1003::docs" >"$main/sshd/users.conf"
    rm -f "$main/userkeys/bob.pub"
    engine restart "$SERVER" >/dev/null
    if wait_healthy "$SERVER"; then pass "server restarts healthy"; else
        fail "server restarts healthy" "$(server_log_tail)"
        return
    fi
    # A restarted container can come back on another address.
    trust_host "$SERVER" "$main"
    capture sftp_password "$CLIENT" alice alice-pw-1 "pwd"
    expect "an old password stops working after restart" eval '((RC != 0)) && has "Permission denied"'
    capture sftp_password "$CLIENT" alice alice-pw-2 "pwd"
    expect "a changed password works after restart" eval '((RC == 0))'
    capture in_server sh -c 'getent passwd dave; test -d /home/dave && echo home-kept'
    expect "a removed user is deleted, home kept" eval 'lacks "dave:" && has home-kept'
    capture sftp_key "$CLIENT" bob bob_key "pwd"
    expect "a revoked key stops working after restart" eval '((RC != 0)) && has "Permission denied"'
    capture engine logs "$SERVER"
    expect "an account left with no password and no key is reported" \
        has "user bob has no password and no key in /config/userkeys, so cannot log in"
    capture in_server fail2ban-client get sshd banip
    expect "bans survive a restart" has "$ATTACKER_IP"

    local start_ns elapsed_ms
    start_ns=$(date +%s%N)
    engine stop -t 30 "$SERVER" >/dev/null
    elapsed_ms=$((($(date +%s%N) - start_ns) / 1000000))
    OUT="stop took ${elapsed_ms} ms, exit code $(engine inspect -f '{{.State.ExitCode}}' "$SERVER")"
    expect "stop is prompt and clean (${elapsed_ms} ms)" eval '((elapsed_ms < 5000)) && has "exit code 0"'
}

# ---------------------------------------------------------------------------
# Supervision: one dead service takes the container down. The auth log cap
# is off here, which rsyslog must accept.
# ---------------------------------------------------------------------------
scenario_crash() {
    SERVER=$RUN_ID-crash
    mkdir -p "$WORK/crash"
    start_server "$SERVER" "$WORK/crash" -e "SFTP_USERS=eve:eve-pw" -e SFTP_AUTH_LOG_MAX_BYTES=0 ||
        die "crash server did not start"
    if wait_healthy "$SERVER"; then pass "starts with SFTP_AUTH_LOG_MAX_BYTES=0 (no cap)"; else
        fail "starts with SFTP_AUTH_LOG_MAX_BYTES=0 (no cap)" "$(server_log_tail)"
        return
    fi
    in_server sh -c 'kill "$(cat /run/sshd.pid)"'
    local _
    for _ in $(seq 15); do
        [[ $(engine inspect -f '{{.State.Running}}' "$SERVER") == false ]] && break
        sleep 1
    done
    OUT="running=$(engine inspect -f '{{.State.Running}} exit={{.State.ExitCode}}' "$SERVER")"
    expect "the container exits non-zero when sshd dies" eval 'has "running=false" && lacks "exit=0"'
}

# ---------------------------------------------------------------------------
# All capabilities dropped except the ones the image needs.
# ---------------------------------------------------------------------------
scenario_hardened() {
    SERVER=$RUN_ID-hardened
    mkdir -p "$WORK/hardened"
    start_server "$SERVER" "$WORK/hardened" --cap-drop ALL \
        --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETUID --cap-add SETGID \
        --cap-add SYS_CHROOT --cap-add KILL --cap-add NET_BIND_SERVICE \
        --security-opt no-new-privileges -e "SFTP_USERS=frank:frank-pw:::up" || die "hardened server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "works with the minimal capability set and no-new-privileges" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$WORK/hardened"
    capture sftp_password "$CLIENT" frank frank-pw "put /client/hello.txt up/hello.txt"
    expect "works with the minimal capability set and no-new-privileges" in_server test -s /home/frank/up/hello.txt
}

# ---------------------------------------------------------------------------
# Custom port from the environment.
# ---------------------------------------------------------------------------
scenario_port() {
    SERVER=$RUN_ID-port
    mkdir -p "$WORK/port"
    start_server "$SERVER" "$WORK/port" -e SFTP_PORT=2222 -e "SFTP_USERS=gina:gina-pw" || die "port server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "SFTP_PORT moves the listener and the health check follows" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$WORK/port" 2222
    capture sftp_password "$CLIENT" gina gina-pw "pwd" -P 2222
    expect "SFTP_PORT moves the listener and the health check follows" eval '((RC == 0))'
}

# ---------------------------------------------------------------------------
# The remaining settings: a secrets file, an upload umask, fail2ban off, a
# time zone, and the strict crypto policy.
# ---------------------------------------------------------------------------
scenario_options() {
    SERVER=$RUN_ID-options
    local options=$WORK/options/config
    mkdir -p "$options"
    printf 'jill:jill-pw:1005:100:drop\n' >"$options/secret-users"
    start_server "$SERVER" "$options" -e SFTP_USERS_FILE=/config/secret-users -e SFTP_UMASK=002 \
        -e FAIL2BAN_ENABLED=false -e TZ=Asia/Kolkata -e SFTP_CRYPTO_POLICY=strict ||
        die "options server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "options server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$options"
    engine exec "$CLIENT" sh -c 'cp /client/hello.txt /tmp/open.txt && chmod 666 /tmp/open.txt'
    capture sftp_password "$CLIENT" jill jill-pw "put /tmp/open.txt drop/open.txt"
    expect "SFTP_USERS_FILE supplies accounts" in_server test -s /home/jill/drop/open.txt
    capture in_server stat -c %a /home/jill/drop/open.txt
    expect "SFTP_UMASK applies to uploads (666 becomes 664)" [ "$OUT" = 664 ]

    capture engine logs "$SERVER"
    expect "FAIL2BAN_ENABLED=false runs and stays healthy without fail2ban" \
        eval 'has "fail2ban is disabled" && ! in_server test -e /run/fail2ban/fail2ban.sock'
    expect "TZ sets the time zone of log timestamps" has "+0530 entrypoint:"

    capture negotiate -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256
    expect "SFTP_CRYPTO_POLICY=strict refuses plain hmac-sha2-256" has "no matching MAC"
    capture negotiate -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256-etm@openssh.com
    expect "SFTP_CRYPTO_POLICY=strict accepts encrypt-then-MAC" eval 'has "Permission denied" && lacks "no matching"'

}

# ---------------------------------------------------------------------------
# A small auth log cap: the log rotates, rsyslog keeps writing, and fail2ban
# still bans from what is written after the rotation.
# ---------------------------------------------------------------------------
scenario_rotation() {
    SERVER=$RUN_ID-rotation
    mkdir -p "$WORK/rotation"
    start_server "$SERVER" "$WORK/rotation" -e SFTP_AUTH_LOG_MAX_BYTES=2048 -e "SFTP_USERS=kim:kim-pw" ||
        die "rotation server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "rotation server becomes healthy" "$(server_log_tail)"
        return
    fi
    in_server sh -c 'for i in $(seq 40); do logger -p auth.info "filler line $i, long enough to pass the cap"; done'
    # The rotation loop reads the size every five seconds.
    local _ rotated=false
    for _ in $(seq 15); do
        if in_server test -s /var/log/auth.log.1; then rotated=true; break; fi
        sleep 1
    done
    capture in_server sh -c 'ls -l /var/log/auth.log*'
    expect "SFTP_AUTH_LOG_MAX_BYTES rotates the auth log" $rotated

    in_server logger -p auth.info "written after the rotation"
    sleep 1
    capture in_server cat /var/log/auth.log
    expect "rsyslog keeps writing the auth log after a rotation" has "written after the rotation"

    in_server sh -c 'for i in 1 2 3 4 5 6; do logger -p auth.info -t "sshd-session[999]" "Failed password for invalid user mallory from 203.0.113.9 port 4444 ssh2"; done'
    local banned=false
    for _ in $(seq 15); do
        capture in_server fail2ban-client get sshd banip
        if has 203.0.113.9; then banned=true; break; fi
        sleep 1
    done
    expect "fail2ban bans from lines written after a rotation" $banned
}

# ---------------------------------------------------------------------------
# rsync through the jail: rhea is opted in on her account line, ray by
# SFTP_RSYNC_USERS, and sam not at all.
# ---------------------------------------------------------------------------
scenario_rsync() {
    SERVER=$RUN_ID-rsync
    local cfg=$WORK/rsync/config user
    mkdir -p "$cfg/sshd"
    printf '%s\n' "rhea:rhea-pw:1101:100:up:rsync" "ray:ray-pw:1102:100:up" "sam:sam-pw:1103:100:up" \
        >"$cfg/sshd/users.conf"
    start_server "$SERVER" "$cfg" -e SFTP_RSYNC_USERS=ray -e SFTP_UMASK=002 || die "rsync server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "rsync server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$cfg"
    engine exec "$CLIENT" sh -c 'head -c 65536 /dev/urandom >/tmp/blob && cp /client/hello.txt /tmp/open.txt && chmod 666 /tmp/open.txt'

    for user in rhea ray; do
        capture rsync_password "$CLIENT" "$user" "$user-pw" /tmp/blob "$SERVER_IP:up/"
        capture in_server stat -c %s:%u "/home/$user/up/blob"
        expect "$user pushes with rsync" [ "$OUT" = "65536:$(in_server id -u "$user")" ]
        capture rsync_password "$CLIENT" "$user" "$user-pw" "$SERVER_IP:up/blob" "/tmp/pulled-$user"
        expect "$user pulls with rsync" engine exec "$CLIENT" cmp /tmp/blob "/tmp/pulled-$user"
    done

    capture rsync_password "$CLIENT" sam sam-pw /tmp/blob "$SERVER_IP:up/"
    expect "an account not allowed rsync cannot use it" eval '((RC != 0)) && ! in_server test -e /home/sam/up/blob'
    capture ssh_password "$CLIENT" rhea rhea-pw id
    expect "the gate refuses commands other than rsync" \
        eval 'has "This service allows sftp and rsync connections only." && lacks "uid="'
    capture rsync_password "$CLIENT" rhea rhea-pw "$SERVER_IP:/etc/passwd" /tmp/stolen-passwd
    expect "rsync stays inside the jail" eval '((RC != 0)) && ! engine exec "$CLIENT" test -s /tmp/stolen-passwd'

    capture sftp_password "$CLIENT" rhea rhea-pw "put /tmp/open.txt up/open.txt"
    capture in_server stat -c %a /home/rhea/up/open.txt
    expect "sftp of an rsync account keeps SFTP_UMASK (666 becomes 664)" [ "$OUT" = 664 ]
    capture in_server ls /home/sam
    expect "an account not allowed rsync gets no binaries in its jail" eval 'lacks bin && lacks usr'
}

# ---------------------------------------------------------------------------
# Per-account permissions and controls from the options on account lines.
# ---------------------------------------------------------------------------
scenario_perms() {
    SERVER=$RUN_ID-perms
    local cfg=$WORK/perms/config
    mkdir -p "$cfg/sshd/sshd_config.d"
    # Refused logins add up to an sshd penalty against the source address;
    # the client is exempt so later checks still connect.
    printf 'PerSourcePenaltyExemptList %s\n' "$CLIENT_IP" >"$cfg/sshd/sshd_config.d/10-test.conf"
    printf '%s\n' "rob:rob-pw:1201:100:pub:readonly" "ula:ula-pw:1202:100:drop:uploadonly" \
        "cara:cara-pw:1203:100:files:perms=list+download+upload+mkdir" "dina:dina-pw:1204:100:up:disabled" \
        "exa:exa-pw:1205:100:up:expires=2000-01-01" "fio:fio-pw:1206:100:up:from=192.0.2.0/24" \
        "gus:gus-pw:1207:100:up:umask=077" "rro:rro-pw:1208:100:pub:rsync,readonly" >"$cfg/sshd/users.conf"
    start_server "$SERVER" "$cfg" || die "perms server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "perms server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$cfg"
    in_server sh -c 'for u in rob ula cara rro; do d=$(ls /home/$u | grep -v -e bin -e lib -e usr | head -1); echo seed >/home/$u/$d/seed.txt; chown $u /home/$u/$d/seed.txt; done'
    engine exec "$CLIENT" sh -c 'cp /client/hello.txt /tmp/open.txt && chmod 666 /tmp/open.txt'

    capture sftp_password "$CLIENT" rob rob-pw $'get pub/seed.txt /tmp/rob-seed\nput /client/hello.txt pub/new.txt'
    expect "a read-only account downloads but cannot upload" \
        eval 'engine exec "$CLIENT" test -s /tmp/rob-seed && ! in_server test -e /home/rob/pub/new.txt'
    capture sftp_password "$CLIENT" ula ula-pw $'put /client/hello.txt drop/in.txt\nget drop/seed.txt /tmp/ula-seed\nrm drop/seed.txt'
    expect "an upload-only account uploads but cannot download or delete" \
        eval 'in_server test -s /home/ula/drop/in.txt && ! engine exec "$CLIENT" test -s /tmp/ula-seed && in_server test -e /home/ula/drop/seed.txt'
    capture sftp_password "$CLIENT" cara cara-pw $'put /client/hello.txt files/up.txt\nrm files/seed.txt\nrename files/up.txt files/moved.txt'
    expect "a custom set without delete and rename refuses both" \
        eval 'in_server test -e /home/cara/files/seed.txt && in_server test -e /home/cara/files/up.txt && ! in_server test -e /home/cara/files/moved.txt'
    capture sftp_password "$CLIENT" dina dina-pw "pwd"
    expect "a disabled account cannot log in" eval '((RC != 0)) && has "Permission denied"'
    capture sftp_password "$CLIENT" exa exa-pw "pwd"
    expect "an expired account cannot log in" eval '((RC != 0)) && has "Permission denied"'
    capture sftp_password "$CLIENT" fio fio-pw "pwd"
    expect "an account limited to other networks is refused" eval '((RC != 0)) && lacks "Remote working directory"'
    capture sftp_password "$CLIENT" gus gus-pw "put /tmp/open.txt up/open.txt"
    capture in_server stat -c %a /home/gus/up/open.txt
    expect "a per-account umask applies (666 becomes 600)" [ "$OUT" = 600 ]

    capture rsync_password "$CLIENT" rro rro-pw "$SERVER_IP:pub/seed.txt" /tmp/rro-seed
    expect "a read-only rsync account pulls" engine exec "$CLIENT" test -s /tmp/rro-seed
    capture rsync_password "$CLIENT" rro rro-pw /client/hello.txt "$SERVER_IP:pub/"
    expect "a read-only rsync account cannot push" eval '((RC != 0)) && has "read-only" && ! in_server test -e /home/rro/pub/hello.txt'
    capture rsync_password "$CLIENT" rro rro-pw --remove-source-files "$SERVER_IP:pub/seed.txt" /tmp/rro-again
    expect "a read-only rsync account cannot remove what it pulls" eval '((RC != 0)) && in_server test -e /home/rro/pub/seed.txt'
}

# ---------------------------------------------------------------------------
# Groups in groups.conf: members take what their own line leaves unset.
# ---------------------------------------------------------------------------
scenario_groups() {
    SERVER=$RUN_ID-groups
    local cfg=$WORK/groups/config
    mkdir -p "$cfg/sshd/sshd_config.d"
    # Refused logins add up to an sshd penalty against the source address;
    # the client is exempt so later checks still connect.
    printf 'PerSourcePenaltyExemptList %s\n' "$CLIENT_IP" >"$cfg/sshd/sshd_config.d/10-test.conf"
    printf '%s\n' "readers:2300:readonly,umask=077" "off::disabled" "partners:2301:uploadonly" "webbers::web" \
        "sharers::sharedays=5,sharepassword" "closed::noshare,sharedays=9" >"$cfg/sshd/groups.conf"
    printf '%s\n' "gra:gra-pw:1301::pub:group=readers" "grb:grb-pw:1302::pub:full,group=readers" \
        "grc:grc-pw:1303::up:group=off" "grd:grd-pw:1304::drop:group=partners,group=readers" \
        "gre:gre-pw:1305::up:group=webbers" "grf:grf-pw:1306::up:sharedays=7,group=sharers,group=closed" \
        >"$cfg/sshd/users.conf"
    start_server "$SERVER" "$cfg" || die "groups server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "groups server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$cfg"
    in_server sh -c 'echo seed >/home/gra/pub/seed.txt && chown gra /home/gra/pub/seed.txt && echo seed >/home/grd/drop/seed.txt && chown grd /home/grd/drop/seed.txt'

    capture sftp_password "$CLIENT" gra gra-pw $'get pub/seed.txt /tmp/gra-seed\nput /client/hello.txt pub/new.txt'
    expect "a group's read-only permissions bind its member" \
        eval 'engine exec "$CLIENT" test -s /tmp/gra-seed && ! in_server test -e /home/gra/pub/new.txt'
    capture sftp_password "$CLIENT" grb grb-pw "put /client/hello.txt pub/new.txt"
    expect "a member's own permissions win over its group's" in_server test -s /home/grb/pub/new.txt
    capture in_server stat -c '%a %g' /home/grb/pub/new.txt
    expect "a member takes its group's umask and gid (600, group 2300)" [ "$OUT" = "600 2300" ]
    capture sftp_password "$CLIENT" grc grc-pw "pwd"
    expect "a disabled group refuses its members' logins" eval '((RC != 0)) && has "Permission denied"'
    capture in_server id -g grd
    expect "the first listed group with a gid gives a member its primary group" [ "$OUT" = 2301 ]
    capture sftp_password "$CLIENT" grd grd-pw $'put /client/hello.txt drop/in.txt\nget drop/seed.txt /tmp/grd-seed'
    expect "permissions from two groups add up (upload-only and read-only)" \
        eval 'in_server test -s /home/grd/drop/in.txt && engine exec "$CLIENT" test -s /tmp/grd-seed'
    capture in_server grep '^gre	' /run/sftp/accounts
    expect "file browser access comes from a group" has $'\tweb,group=webbers\t'
    capture in_server grep '^grf	' /run/sftp/accounts
    expect "every share link limit applies, the shortest length among them" \
        has $'\tnoshare,sharedays=5,sharepassword,group=sharers,group=closed\t'
}

# ---------------------------------------------------------------------------
# Country rules: the table they load, a source in no listed country let in
# by block and dropped by allow, the never-ban list as an exemption, a bad
# code refused, and the table removed when the rule is off. The far client
# sits on $FARNET; the usual client's private address always passes.
# ---------------------------------------------------------------------------
scenario_countries() {
    SERVER=$RUN_ID-countries
    local cfg=$WORK/countries/config far=$RUN_ID-far near_ip key
    local far_ip=198.51.100.20 server_far_ip=198.51.100.10
    mkdir -p "$cfg/sshd" "$cfg/fail2ban/jail.d"
    printf '%s\n' "cora:cora-pw:1301::up" >"$cfg/sshd/users.conf"
    printf '%s\n' "SFTP_COUNTRY_RULE=block" "SFTP_COUNTRIES=CN, ru" >"$cfg/sshd/settings.conf"
    # As the web UI writes it, plus a host name only a hand edit could add.
    printf '[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 192.0.2.0/24 gateway.example\n' >"$cfg/fail2ban/jail.d/00-webui.local"
    start_server "$SERVER" "$cfg" || die "countries server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "countries server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$cfg"
    near_ip=$SERVER_IP
    capture engine logs "$SERVER"
    expect "a never-ban host name is reported and the server still starts" \
        has "cannot exempt a never-ban entry: gateway.example"
    capture in_server cat /run/sftp/country-rules
    expect "the country rules are enforced and recorded" eval 'has "enforced=yes" && has "countries=CN RU"'
    capture in_server nft list set inet sftp_countries a_ports
    expect "the rules guard sshd's port" has "elements = { 22 }"
    capture in_server nft list set inet sftp_countries a_exempt4
    expect "the never-ban networks pass, read as fail2ban reads them" eval 'has "192.0.2.0/24" && has "127.0.0.0/8"'
    capture in_server nft list set inet sftp_countries a_listed4_0
    expect "the listed countries' networks are loaded" has "elements = {"

    engine network create --subnet 198.51.100.0/24 "$FARNET" >/dev/null || die "cannot create network $FARNET"
    engine network connect --ip "$server_far_ip" "$FARNET" "$SERVER" || die "cannot attach $SERVER to $FARNET"
    engine run -d --name "$far" --network "$FARNET" --ip "$far_ip" -v "$WORK/client:/client:ro" "$IMAGE" \
        sleep infinity >/dev/null || die "cannot start the far client"
    key=$(cat "$cfg/sshd/keys/ssh_host_ed25519_key.pub") || die "no host key in $cfg"
    printf '%s %s\n' "$server_far_ip" "$key" >>"$WORK/client/known_hosts"
    SERVER_IP=$server_far_ip
    capture sftp_password "$far" cora cora-pw "pwd"
    expect "block lets in a source in no listed country" eval '((RC == 0))'

    printf '%s\n' "SFTP_COUNTRY_RULE=allow" "SFTP_COUNTRIES=IS" >"$cfg/sshd/settings.conf"
    capture in_server entrypoint apply
    expect "apply loads allow mode" eval '((RC == 0)) && has "country rules: allow IS on port(s) 22"'
    capture in_server nft list chain inet sftp_countries input
    expect "a reload points the rules at the sets it filled" \
        eval 'has "ip saddr @b_listed4_0 accept" && has "tcp dport @b_ports drop" && lacks "@a_"'
    capture in_server nft -t list table inet sftp_countries
    expect "a reload deletes the sets the rules read before" eval '((RC == 0)) && has "set b_ports" && lacks "set a_"'
    capture sftp_password "$far" cora cora-pw "pwd"
    expect "allow drops a source in no listed country" eval '((RC != 0)) && has "timed out"'
    SERVER_IP=$near_ip
    capture sftp_password "$CLIENT" cora cora-pw "pwd"
    expect "a private address passes allow" eval '((RC == 0))'

    printf '[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 198.51.100.0/24\n' >"$cfg/fail2ban/jail.d/00-webui.local"
    capture in_server entrypoint apply
    SERVER_IP=$server_far_ip
    capture sftp_password "$far" cora cora-pw "pwd"
    expect "a never-ban network passes allow" eval '((RC == 0))'

    printf '%s\n' "SFTP_COUNTRY_RULE=block" "SFTP_COUNTRIES=CN CHN" >"$cfg/sshd/settings.conf"
    capture in_server entrypoint apply
    expect "apply refuses a country code that is not two letters" \
        eval '((RC != 0)) && has "CHN is not a two-letter country code"'

    printf 'SFTP_COUNTRY_RULE=off\n' >"$cfg/sshd/settings.conf"
    capture in_server entrypoint apply
    capture in_server nft list table inet sftp_countries
    expect "turning the rule off removes the table" eval '((RC != 0)) && ! in_server test -e /run/sftp/country-rules'
}

# ---------------------------------------------------------------------------
# The file browser's sshd: loopback only, logins by the file browser's
# certificates only and only for accounts with web access, each account's
# own permissions applied; the public port does not trust those certificates.
# ---------------------------------------------------------------------------
scenario_browser() {
    SERVER=$RUN_ID-browser
    local cfg=$WORK/browser/config
    mkdir -p "$cfg/sshd"
    printf '%s\n' "wan:wan-pw:1501::up:web,readonly" "nob:nob-pw:1502::up" >"$cfg/sshd/users.conf"
    cp -- "$FIXTURES/files-sshd-probe.sh" "$cfg/probe.sh"
    start_server "$SERVER" "$cfg" -e WEBUI_ENABLED=true -e WEBUI_FILES_ENABLED=true || die "browser server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "browser server becomes healthy" "$(server_log_tail)"
        return
    fi
    # 2299 is 08FB in /proc/net/tcp; 0A is LISTEN.
    capture in_server awk '$2 ~ /:08FB$/ && $4 == "0A" { print $2 }' /proc/net/tcp /proc/net/tcp6
    expect "the file browser's sshd listens on loopback alone" [ "$OUT" = "0100007F:08FB" ]
    capture in_server sh /config/probe.sh
    expect "a file browser certificate logs in on loopback" has "loopback-list ok"
    expect "the account's own permissions apply there (read-only refuses an upload)" has "loopback-upload refused"
    expect "the public port refuses the file browser's certificates" has "public-port refused"
    expect "an account without web access cannot log in there" has "no-web-access refused"
    capture in_server stat -c '%a %U' /config/sshd/keys/files_ca
    expect "the certificate authority's key is root's alone" [ "$OUT" = "600 root" ]
}

# ---------------------------------------------------------------------------
# entrypoint apply: changes to /config take effect while the server runs,
# and open sessions stay connected.
# ---------------------------------------------------------------------------
scenario_apply() {
    SERVER=$RUN_ID-apply
    local cfg=$WORK/apply/config _
    mkdir -p "$cfg/sshd"
    printf '%s\n' "ann:ann-pw:1301:100:up" "staff:staff-pw:1302:100:up" >"$cfg/sshd/users.conf"
    start_server "$SERVER" "$cfg" || die "apply server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "apply server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$cfg"
    # A session that stays open for the whole scenario.
    engine exec -d -e SSH_ASKPASS=/client/askpass -e SSH_ASKPASS_REQUIRE=force -e TEST_PASSWORD=ann-pw "$CLIENT" \
        sh -c "sleep 60 | sftp ${SSH_OPTS[*]} -o PubkeyAuthentication=no ann@$SERVER_IP" >/dev/null
    for _ in $(seq 10); do has_session ann && break; sleep 1; done
    capture process_titles
    expect "a session opens for the apply checks" has_session ann

    printf '%s\n' "ann:ann-pw:1301:100:up" "ben:ben-pw:1303:100:up" >"$cfg/sshd/users.conf"
    capture in_server entrypoint apply
    expect "entrypoint apply reports success" eval '((RC == 0)) && has "applied"'
    capture sftp_password "$CLIENT" ben ben-pw "pwd"
    expect "an account added to users.conf logs in without a restart" eval '((RC == 0))'
    capture in_server sh -c 'getent passwd staff; getent group staff >/dev/null && echo group-kept'
    expect "a removed account named like a group leaves the group" eval 'lacks "staff:x" && has group-kept'
    expect "an open session survives apply" has_session ann

    printf 'SFTP_PORT=2222\n' >"$cfg/sshd/settings.conf"
    capture in_server entrypoint apply
    trust_host "$SERVER" "$cfg" 2222
    capture sftp_password "$CLIENT" ben ben-pw "pwd" -P 2222
    expect "settings.conf moves the port live" eval '((RC == 0))'
    expect "the health check follows the new port" in_server /usr/local/bin/healthcheck

    printf '%s\n' "ann:ann-pw:1301:100:up" "ben:ben-pw:0" >"$cfg/sshd/users.conf"
    capture in_server entrypoint apply
    expect "apply refuses a bad line and changes nothing" eval '((RC != 0)) && has "0 is root" && in_server getent passwd ben >/dev/null'

    printf '%s\n' "ann:ann-pw:1301:100:up:disabled" "ben:ben-pw:1303:100:up" >"$cfg/sshd/users.conf"
    capture in_server entrypoint apply
    expect "disabling an account ends its open session" eval '((RC == 0)) && ! has_session ann'
}

# ---------------------------------------------------------------------------
# The admin web UI, driven over HTTPS by tests/webui_driver.py.
# ---------------------------------------------------------------------------
# web <container> <step> [args...]: runs one driver step and records each
# check it prints.
web() {
    local from=$1 line rest other=""
    shift
    while IFS= read -r line; do
        case $line in
            "ok "*) pass "web UI: ${line#ok }" ;;
            "not ok "*) fail "web UI: ${line#not ok }" ;;
            "skip "*)
                rest=${line#skip }
                skip "web UI: ${rest%%: *}" "${rest#*: }"
                ;;
            *) other+=$line$'\n' ;;
        esac
    done < <(engine exec "$from" python3 /client/webui_driver.py "https://$SERVER_IP:8443" "$@" 2>&1)
    if [[ -n $other ]]; then fail "web UI step $1 ran to the end" "$other"; fi
    if [[ $(engine inspect -f '{{.State.Running}}' "$SERVER") != true ]]; then
        fail "the web UI server is still running after step $1" "$(server_log_tail)"
    fi
}

scenario_webui() {
    local cfg=$WORK/webui/config token
    mkdir -p "$WORK/webui-off" "$cfg/sshd"
    SERVER=$RUN_ID-webui-off
    start_server "$SERVER" "$WORK/webui-off" -e "SFTP_USERS=wes:wes-pw" || die "web UI off server did not start"
    if wait_healthy "$SERVER"; then
        # 8443 is 20FB in /proc/net/tcp.
        expect "the web UI is off by default" \
            eval '! in_server grep -qs ":20FB " /proc/net/tcp /proc/net/tcp6 && ! in_server test -e /run/sftp-webui'
    else
        fail "the web UI is off by default" "$(server_log_tail)"
    fi
    engine rm -f "$SERVER" >/dev/null

    reject "refuses plain HTTP without trusted proxies" "needs WEBUI_TRUSTED_PROXIES" wes:pw \
        -e WEBUI_ENABLED=true -e WEBUI_PLAIN_HTTP=true

    SERVER=$RUN_ID-webui
    printf '%s\n' "wes:wes-pw:1401:100:up" >"$cfg/sshd/users.conf"
    # The client may forward an address, as a reverse proxy does, so the
    # countries step can present one from outside the private ranges.
    start_server "$SERVER" "$cfg" -e WEBUI_ENABLED=true -e WEBUI_TRUSTED_PROXIES="$CLIENT_IP" \
        -e WEBUI_FILES_ENABLED=true || die "web UI server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "web UI server becomes healthy" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$cfg"
    token=$(engine logs "$SERVER" 2>&1 | grep -o 'setup?token=[A-Za-z0-9_-]*' | tail -1 | cut -d= -f2)
    expect "the log prints a one-time setup link" [ -n "$token" ]
    capture in_server stat -c %a /config/webui/tls/key.pem
    expect "the generated TLS key is mode 600" [ "$OUT" = 600 ]

    web "$CLIENT" fresh
    web "$CLIENT" setup "$token" boss "boss-password-123"
    web "$CLIENT" protections
    web "$CLIENT" create-account webby "webby-password-1"
    capture sftp_password "$CLIENT" webby webby-password-1 $'pwd\nput /client/hello.txt up/x.txt'
    expect "an account made in the UI logs in, read-only" eval '((RC == 0)) && ! in_server test -e /home/webby/up/x.txt'
    web "$CLIENT" activity webby
    in_server sh -c 'printf "hello from sftp\n" >/home/webby/up/hello.txt'
    web "$CLIENT" files webby
    web "$CLIENT" create-account fuller "fuller-password-1" full
    in_server sh -c 'printf "hello from sftp\n" >/home/fuller/up/hello.txt'
    # A name meant to run as markup if the page did not escape it.
    in_server sh -c 'printf x >"/home/fuller/up/<img src=x onerror=alert(1)>.txt"'
    web "$CLIENT" files fuller full
    web "$CLIENT" grant-manage webby fuller
    web "$CLIENT" manager webby fuller
    capture in_server grep -c ':\$y\$' /config/sshd/users.conf
    expect "the UI stores both accounts' passwords as yescrypt hashes" [ "$OUT" = 2 ]
    web "$CLIENT" settings
    capture in_server cat /config/sshd/settings.conf
    expect "the setting lands in settings.conf" has "SFTP_UMASK=027"
    web "$CLIENT" bans 203.0.113.50
    web "$CLIENT" countries
    web "$CLIENT" invite "reader-password-1"
    web "$CLIENT" totp boss "boss-password-123"
    web "$CLIENT" audit
    web "$CLIENT" delete-account webby
    capture sftp_password "$CLIENT" webby webby-password-1 "pwd"
    expect "an account deleted in the UI can no longer log in" eval '((RC != 0)) && has "Permission denied"'
    web "$CLIENT" logout

    web "$ATTACKER" lockout boss
    local _ banned=false
    for _ in $(seq 20); do
        capture in_server fail2ban-client get sftp-webui banip
        if has "$ATTACKER_IP"; then banned=true; break; fi
        sleep 1
    done
    expect "failed web logins are banned by fail2ban" $banned
    capture in_server sh -c 'stat -c "%U %a" /config/webui/admins.json; stat -c "%U %a" /config/audit/webui.log'
    expect "the admin store belongs to the web UI and the audit log to root" eval 'has "sftp-webui 600" && has "root 600"'
}

# ---------------------------------------------------------------------------
# 1.x configuration in /config, untouched and edited.
# ---------------------------------------------------------------------------
scenario_legacy() {
    SERVER=$RUN_ID-legacy
    local legacy=$WORK/legacy/config
    mkdir -p "$legacy/sshd" "$legacy/fail2ban"
    cp "$FIXTURES/legacy-1.x/sshd_config" "$legacy/sshd/sshd_config"
    cp "$FIXTURES/legacy-1.x/jail.conf" "$legacy/fail2ban/jail.conf"
    printf '[Definition]\nloglevel = INFO\n' >"$legacy/fail2ban/fail2ban.conf"
    start_server "$SERVER" "$legacy" -- hank:hank-pw || die "legacy server did not start"
    if wait_healthy "$SERVER"; then pass "starts with an untouched 1.x /config"; else
        fail "starts with an untouched 1.x /config" "$(server_log_tail)"
    fi
    expect "untouched 1.x defaults are renamed to *.legacy" eval \
        '[[ -f $legacy/sshd/sshd_config.legacy && -f $legacy/fail2ban/jail.conf.legacy && -f $legacy/fail2ban/fail2ban.conf.legacy && ! -e $legacy/sshd/sshd_config ]]'
    capture in_server /usr/sbin/sshd -T
    expect "the built-in hardened sshd configuration replaces them" has "allowgroups sftpusers"

    SERVER=$RUN_ID-custom
    local custom=$WORK/custom/config
    mkdir -p "$custom/sshd" "$custom/userkeys"
    { cat "$FIXTURES/legacy-1.x/sshd_config"; printf '# edited by the administrator\n'; } >"$custom/sshd/sshd_config"
    cp "$WORK/client/bob_key.pub" "$custom/userkeys/ivan.pub"
    start_server "$SERVER" "$custom" -- ivan:: || die "custom server did not start"
    if ! wait_healthy "$SERVER"; then
        fail "an edited 1.x sshd_config is honored, with a warning" "$(server_log_tail)"
        return
    fi
    trust_host "$SERVER" "$custom"
    capture engine logs "$SERVER"
    expect "an edited 1.x sshd_config is honored, with a warning" \
        eval '[[ -f $custom/sshd/sshd_config ]] && has "replaces the whole built-in sshd configuration"'
    capture sftp_key "$CLIENT" ivan bob_key "pwd"
    expect "key logins still work under an edited 1.x sshd_config" [ "$RC" = 0 ]
}

# ---------------------------------------------------------------------------
# Configuration errors stop the container before anything listens.
# ---------------------------------------------------------------------------
# reject <name> <message> <spec> [engine run options...]
reject() {
    local name=$1 message=$2 spec=$3
    shift 3
    capture timeout 60 "$ENGINE" run --rm "$@" "$IMAGE" "$spec"
    # A rejected configuration must stop before any host key is made.
    if ((RC != 0)) && has "$message" && lacks "host key"; then pass "$name"; else fail "$name" "$OUT"; fi
}

scenario_reject() {
    reject "refuses to take over a system account" "system account of the image" root:pw
    reject "refuses uid 0" "0 is root" eve:pw:0
    reject "refuses directories that climb out of home" "may not contain . or .." eve:pw:::../etc
    reject "refuses absolute directories" "must be relative" eve:pw:::/etc
    reject "refuses a non-numeric uid" "must be a number" eve:pw:abc
    reject "refuses an unknown crypto policy" "must be modern or strict" eve:pw -e SFTP_CRYPTO_POLICY=weak
    reject "refuses a malformed auth log cap" "is not a byte count" eve:pw -e SFTP_AUTH_LOG_MAX_BYTES=10MB
    reject "refuses an out-of-range port" "is not a port number" eve:pw -e SFTP_PORT=70000
    reject "refuses a flag that is not true or false" "FAIL2BAN_ENABLED=maybe must be true or false" \
        eve:pw -e FAIL2BAN_ENABLED=maybe
    reject "refuses an unknown option after the directories" 'unknown option "shell"' eve:pw:::up:shell
    reject "refuses the web UI's uid" "belongs to the image's web UI account" eve:pw:980
    reject "refuses a network with host bits set" "has host bits set" eve:pw:::up:from=10.0.0.1/8
    reject "refuses rsync with upload-only permissions" "rsync works only with full or read-only" eve:pw:::up:rsync,uploadonly
    reject "refuses a share link length that is not a number of days" "sharedays=0 is not a number of days" eve:pw:::up:sharedays=0
    reject "refuses noshare given twice" "option noshare is given twice" eve:pw:::up:noshare,noshare
    reject "refuses SFTP_RSYNC_USERS naming an unknown account" "not a configured account" \
        eve:pw -e SFTP_RSYNC_USERS=mallory
    reject "refuses an unknown country rule" "is not off, block or allow" eve:pw -e SFTP_COUNTRY_RULE=deny
    reject "refuses half a MaxMind key" "set both or neither" eve:pw -e MAXMIND_ACCOUNT_ID=123456
    reject "refuses the file browser without the admin web UI" "needs WEBUI_ENABLED=true" eve:pw -e WEBUI_FILES_ENABLED=true

    mkdir -p "$WORK/empty"
    capture timeout 60 "$ENGINE" run --rm -v "$WORK/empty:/config" "$IMAGE"
    expect "exits 3 with no users and writes a users.conf template" \
        eval '((RC == 3)) && grep -q "one per line" "$WORK/empty/sshd/users.conf"'

    capture timeout 60 "$ENGINE" run --rm "$IMAGE" sh -c 'echo ran-instead'
    expect "a non-user command runs in place of the server" eval '((RC == 0)) && has ran-instead && lacks "host key"'
}

# ---------------------------------------------------------------------------
# Setup, then the selected scenarios.
# ---------------------------------------------------------------------------
[[ -n $ENGINE ]] || die "neither docker nor podman is installed"
read -r -a SELECTED <<<"${SCENARIOS:-${ALL_SCENARIOS[*]}}"
for s in "${SELECTED[@]}"; do
    declare -F "scenario_$s" >/dev/null || die "unknown scenario \"$s\"; known: ${ALL_SCENARIOS[*]}"
done

if [[ -z $IMAGE ]]; then
    IMAGE=localhost/sftp:test
    build=(build -t "$IMAGE")
    [[ $(basename "$ENGINE") == podman ]] && build+=(--format docker)
    engine "${build[@]}" . >"$WORK/build.log" 2>&1 || { tail -40 "$WORK/build.log"; die "image build failed"; }
fi
printf '# engine %s, image %s, scenarios: %s\n' "$ENGINE" "$IMAGE" "${SELECTED[*]}"

mkdir -p "$WORK/client"
printf '#!/bin/sh\nprintf "%%s\\n" "$TEST_PASSWORD"\n' >"$WORK/client/askpass"
chmod 755 "$WORK/client/askpass"
printf 'hello from the test suite\n' >"$WORK/client/hello.txt"
cp tests/webui_driver.py "$WORK/client/webui_driver.py"
engine run --rm -v "$WORK/client:/client" "$IMAGE" sh -c \
    'ssh-keygen -q -t ed25519 -N "" -C bob -f /client/bob_key &&
     ssh-keygen -q -t ed25519 -N "" -C stranger -f /client/stranger_key' || die "key generation failed"
CAROL_HASH=$(engine run --rm "$IMAGE" mkpasswd -m yescrypt carol-pw-1) || die "mkpasswd failed"
[[ $CAROL_HASH == \$y\$* ]] || die "mkpasswd returned \"$CAROL_HASH\""

engine network create "$NET" >/dev/null || die "cannot create network $NET"
engine run -d --name "$CLIENT" --network "$NET" -v "$WORK/client:/client:ro" "$IMAGE" sleep infinity >/dev/null
engine run -d --name "$ATTACKER" --network "$NET" -v "$WORK/client:/client:ro" "$IMAGE" sleep infinity >/dev/null
CLIENT_IP=$(ip_of "$CLIENT")
ATTACKER_IP=$(ip_of "$ATTACKER")
[[ -n $CLIENT_IP && -n $ATTACKER_IP ]] || die "client containers have no address"

for s in "${SELECTED[@]}"; do
    printf '# scenario %s\n' "$s"
    "scenario_$s"
done

printf '\n# %d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
if ((FAILED)); then
    printf '# failed: %s\n' "${FAILURES[@]}"
    exit 1
fi
