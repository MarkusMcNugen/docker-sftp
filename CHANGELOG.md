# Changelog

## 2.2.1

- The Status page, the accounts list and every account page opened with an error whenever an SFTP client was connected. The open sessions now take their address from the login sshd logged, so the pages no longer need to read sshd's sockets, which a container without `CAP_SYS_PTRACE` cannot do.
- A session the file browser opens for its user shows as "File browser" instead of 127.0.0.1.
- Sizes, intervals and times in the web UI, the file browser and their messages use unit symbols: 694 B, 845 kB, 2.4 MB, 10 s.
- The documentation shows the web UI and the command line side by side in each how-to, with screenshots, and the README opens with the dashboard.

## 2.2.0

### Admin web UI

- An optional admin web UI (`WEBUI_ENABLED=true`, HTTPS on port 8443) for accounts, public keys, permissions, settings, fail2ban bans and rules, live sessions, logs and an audit log. Changes apply at once, without a restart. [How To Use The Admin Web UI](https://markusmcnugen.github.io/docker-sftp/docs/how-to/use-the-web-ui/) covers it.
- Several named admins, with full or read-only roles, added by one-time invite links; argon2id passwords, optional TOTP codes, and a setup link printed in the log for the first admin, or admins supplied in `WEBUI_ADMIN_FILE`.
- Failed sign-ins lock an address out and feed a new fail2ban jail, `sftp-webui`.
- The web server runs unprivileged and talks to a root helper over a Unix socket. The helper accepts a fixed list of validated requests and records every change in `/config/audit/webui.log`.
- Passwords set in the UI are stored as yescrypt hashes, and one action hashes every plain-text password left in `users.conf`.
- Pages for groups, activity and country rules, with Phosphor icons, the Geist fonts and country flags; the colors follow the system's light or dark mode.

### Accounts

- Permissions per account, enforced by OpenSSH: `readonly`, `uploadonly`, or `perms=` with any of list, download, upload, delete, rename, mkdir, attributes and links. Read-only rsync accounts may only download.
- `disabled`, `expires=YYYY-MM-DD`, `from=` (allowed networks) and `umask=` per account.
- These are options at the end of the account line, after the directories; the 2.1 `rsync` field is the first of them, so existing lines keep working.
- Disabling, expiring or removing an account ends its open sessions.
- Removing an account named like a group, such as `staff`, no longer deletes that group.
- uid and gid 980 and 981 belong to the web UI's and the file browser's accounts and are refused.

### Groups and managers

- Groups in `/config/sshd/groups.conf`, one per line as `name[:gid[:options]]`, give their members defaults: grants add up across an account's groups, limits take the strictest, and what the account's own line sets wins. [How To Group Accounts](https://markusmcnugen.github.io/docker-sftp/docs/how-to/group-accounts/) covers them.
- `group=name` on an account line joins a group; the first of an account's groups with a gid gives it its primary group.
- `manage=name` and `manage=@group` let an account open other accounts' files in the file browser, with each account's own permissions; what it does there is logged under both names.

### History and activity

- Every sign-in and file operation, over SFTP and in the file browser, is kept in a permanent history in `/config/webui/history.sqlite3`. The Activity page shows it live and opens on who is connected now or was active in the last 24 hours.
- What is done in the file browser is recorded as done there, with the person who did it and their address, including what a manager does in another account's files and a share link's download.
- Every ban fail2ban makes is kept, so the Bans page shows past bans beside the current ones.
- Charts of sign-ins and transfers on the Status page, and of bans per period and the names tried on the Bans page.

### Country rules

- `SFTP_COUNTRY_RULE=block` drops new connections from the countries in `SFTP_COUNTRIES` to sshd's ports, the web UI's and the file browser's; `allow` drops every other country instead. Loopback, private ranges, `WEBUI_TRUSTED_NETWORKS` and fail2ban's never-ban list always pass. [How To Block Countries](https://markusmcnugen.github.io/docker-sftp/docs/how-to/block-countries/) covers them.
- The rules are enforced with nftables in the container's network namespace, which needs `NET_ADMIN`, and by the web servers themselves.
- The image carries DB-IP's IP to Country Lite database, refreshed by the weekly rebuild. With `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY`, set in the environment or on the Settings page, MaxMind GeoLite2 replaces it and is kept current.
- A Countries card on the Bans page sets the rules, and the page shows the country of each ban.
- The country lists load in batches that a container in a user namespace can send, such as under rootless Podman, and a reload switches the rules to the new lists in one step.

### File browser

- `WEBUI_FILES_ENABLED=true` serves a file browser on its own port, `WEBUI_FILES_PORT` (8444), to accounts with the `web` option on their own line or from a group. [How To Use The File Browser](https://markusmcnugen.github.io/docker-sftp/docs/how-to/use-the-file-browser/) covers it.
- An admin makes a one-time sign-in link for each account. Its holder sets a web password of at least 12 characters, kept as an argon2id hash, and enrolls an authenticator app; a code is asked at every sign-in except from `WEBUI_TRUSTED_NETWORKS`, and each code works once.
- The file browser works through SFTP on a loopback sshd with certificates that last five minutes, so each account's permissions and jail apply as they do over SFTP, and every operation is logged the same way.
- A three-pane file manager: the folder tree, the files as a list or a grid, and the details of the chosen one.
- Uploads stream to disk with no size limit, folders included, and an upload that stopped goes on from where the server's copy ends.
- Rename, move, copy, delete and new folders, for one item or a selection.
- Previews of pictures, PDFs, audio, video and text.
- Folders and selections download as zip files, streamed as they are made.
- Search by name in a folder and every folder below it.
- The details pane shows who added a file, from where and how, and everything done with it since.
- Inside a zip, tar, tar.gz or tgz archive: its entries listed, one downloaded, or all unpacked beside it; an entry whose path would leave the folder, and a link, are refused.
- Managers open the files of the accounts they manage.
- Share links: a link to one file that works for one download and lasts seven days unless its maker picks another length, with an optional password. The token travels after the `#` and is kept only as its SHA-256.
- `FILES_SHARE`, `FILES_SHARE_DAYS`, `FILES_SHARE_MAX_DAYS` and `FILES_SHARE_PASSWORD` set the share link policy. `noshare`, `sharedays=N` and `sharepassword` on an account or group line only tighten it, for the account's files and for the links it makes.
- A wrong share link password counts toward the address's sign-in lockout and fail2ban.

### Configuration

- `docker exec <container> entrypoint apply` applies changes in `/config` to the running server; open sessions stay connected.
- `/config/sshd/settings.conf` holds `SFTP_PORT`, `SFTP_LOG_TRANSFERS`, `SFTP_UMASK`, `SFTP_CRYPTO_POLICY`, `SFTP_AUTH_LOG_MAX_BYTES`, `SFTP_COUNTRY_RULE`, `SFTP_COUNTRIES` and the four `FILES_SHARE` settings; the container's environment wins over it.

### Project

- A new logo, kept in this repository: the folder and prompt redrawn flat, with an outline version for the web UI and its favicon.
- The web UI is built with Rust 1.100.

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
