# Changelog

## 2.1.0

- rsync over SSH for chosen accounts, inside their jails: end an account
  line with `:rsync`, or name the account in `SFTP_RSYNC_USERS` (`*` for
  every account). The account's login shell becomes a gate that runs only
  an rsync server command, and its jail gets root-owned copies of `sh`,
  `rsync` and their libraries, refreshed on every start and removed when
  the account loses rsync. Other accounts stay SFTP-only.
- `SFTP_LOG_TRANSFERS` and `SFTP_UMASK` also apply through the sftp
  `Subsystem` line, so accounts allowed rsync keep both.
- rsync is installed in the image.

## 2.0.0

A rewrite. The `users.conf` format and the `/config` layout are kept, and a
1.x `/config` is read without changes; [How To Upgrade From
1.x](https://markusmcnugen.github.io/docker-sftp/docs/how-to/upgrade-from-1x/)
lists what moves.

### Platform

- Base image is `debian:trixie-slim` (Debian 13) instead of
  `phusion/baseimage:master-amd64` (Ubuntu): OpenSSH 10.0, fail2ban 1.1,
  Python 3.13.
- The image is 146.6 MB instead of 357 MB; systemd is not installed.
- Images for `linux/amd64` and `linux/arm64`, each tested on a native runner
  of its architecture, published to Docker Hub and GHCR with an SBOM and
  provenance. A weekly build republishes the newest release with Debian's
  security updates.
- tini is process 1, and the entrypoint supervises rsyslogd, fail2ban and
  sshd. `docker stop` takes under a second instead of running into the
  10-second kill timeout, and the container exits non-zero when any service
  dies, so the restart policy recovers it.
- A health check reports whether sshd listens and fail2ban runs.

### Security

- Hardened sshd: post-quantum hybrid key exchange (`mlkem768x25519-sha256`)
  first; no SHA-1, CBC, MD5 or 64-bit MACs; group-exchange moduli of at
  least 3072 bits; `RequiredRSASize 2048`; `MaxAuthTries 4`;
  `LoginGraceTime 30`; every kind of forwarding, TTYs and client
  environment disabled; `LogLevel VERBOSE` records key fingerprints.
- Only accounts the entrypoint creates can log in (`AllowGroups sftpusers`),
  and their shell is `nologin`.
- Authorized keys are installed root-owned in `/etc/ssh/authorized_keys/`,
  outside every jail. In 1.x a user could upload their own
  `authorized_keys`.
- fail2ban bans every port of the offending address, so a custom sshd port
  is covered, and repeat offenders get doubling bans up to a week.
- The entrypoint checks at start whether fail2ban can change firewall rules
  and says so. 1.x needed `NET_ADMIN` too but never documented it, so on a
  default `docker run` it detected attacks and never banned.
- The container runs under `--cap-drop ALL` with ten capabilities and
  `no-new-privileges`, which the test suite checks.

### Accounts

- Every start reconciles accounts with the configuration. 1.x skipped an
  account that already existed, so after a container restart a changed
  password, a removed user or a removed key kept working.
- Every account line and every environment variable is validated before
  anything is created, and a mistake stops the container with one line.
  Refused: uid or gid 0, the image's own system accounts, and directories
  that are absolute or contain `.` or `..` (1.x created and chowned any
  path, such as `../../etc`).
- Passwords are never logged. 1.x printed each account line, password
  included.
- Nested directories such as `data/inbox` belong to the user at every
  level, and a symbolic link planted by a user cannot redirect the root-run
  `mkdir` and `chown` outside the jail.
- A user without a gid gets group 100 (`users`), and directories the
  entrypoint creates get the user's own group instead of always `users`.
- Windows line endings in `users.conf` and key files are handled.
- An account with neither a password nor a key is reported at start.
- New: `SFTP_USERS_FILE` for Docker secrets, several keys per user in
  `/config/userkeys/<name>/*.pub`, and `mkpasswd` in the image for yescrypt
  hashes.

### Configuration

- sshd overrides go in `/config/sshd/sshd_config.d/*.conf`, and fail2ban
  overrides in `/config/fail2ban/jail.local`, `jail.d/`, `filter.d/`,
  `action.d/` and `fail2ban.local`, which image updates never overwrite.
- An untouched 1.x `sshd_config` or `jail.conf` in `/config` (recognized by
  SHA-256 against every version 1.x shipped) is renamed `*.legacy`. An
  edited one is still used as the complete configuration, with a warning.
  `fail2ban.conf` is renamed `*.legacy`.
- Both configurations are validated before the services start, and a
  mistake stops the container with sshd's or fail2ban's own message.
- New settings: `SFTP_PORT`, `SFTP_UMASK`, `SFTP_CRYPTO_POLICY`,
  `SFTP_AUTH_LOG_MAX_BYTES`, `FAIL2BAN_ENABLED`, `TZ`, and
  `SFTP_LOG_TRANSFERS` for a log of every file operation.
- Startup scripts ending in `.sh` run without the executable bit.
- With no account configured, a commented `users.conf` template is written
  and the container exits with status 3.

### Logging

- Everything goes to `docker logs`. fail2ban no longer writes
  `/config/fail2ban/fail2ban.log`, which 1.x grew without limit.
- syslog-ng is replaced by a minimal rsyslog with rate limiting off, so no
  failed login is dropped during an attack. The internal auth log is copied
  aside and emptied at `SFTP_AUTH_LOG_MAX_BYTES`, which works even where a
  host security policy confines rsyslogd.

### Project

- An integration suite (`tests/run-tests.sh`) for Docker and Podman, with
  selectable scenarios.
- The release workflow runs shellcheck, hadolint, the suite on both
  architectures and a Trivy scan before publishing; actions are pinned by
  commit SHA and kept current by Dependabot.
- A wiki: a tutorial, twelve how-to guides, two explanations and six
  reference pages.
- `compose.yaml`, a deployment with every hardening option.

## 1.x

Ubuntu-based releases, forked from atmoz/sftp for unRAID.
