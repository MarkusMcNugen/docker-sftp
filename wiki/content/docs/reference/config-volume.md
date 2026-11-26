---
title: The /config Volume
weight: 3
---

| Path | Read or written | When |
|---|---|---|
| `sshd/users.conf` | read; written as a commented template when no account exists anywhere; the web UI edits it | every start |
| `sshd/groups.conf` | read; the web UI edits it ([How To Group Accounts](../../how-to/group-accounts/)) | every start |
| `sshd/settings.conf` | read, under the environment; the web UI's Settings page writes it | every start |
| `sshd/keys/ssh_host_ed25519_key`, `ssh_host_rsa_key` (and `.pub`) | generated when missing, then read; private keys set to mode 600 | every start |
| `sshd/keys/files_ca` (and `.pub`) | the file browser's certificate authority, generated when missing; only the root helper signs with it | every start, with the file browser on |
| `sshd/sshd_config.d/*.conf` | copied to `/etc/ssh/sshd_config.d/` | every start |
| `sshd/sshd_config` | an untouched 1.x default is renamed `.legacy`; an edited one replaces the built-in configuration | every start |
| `sshd/scripts/*` | executable files and `.sh` files run as root, in name order | every start, after accounts exist |
| `userkeys/<name>.pub`, `userkeys/<name>/*.pub` | public keys, installed for `<name>` | every start |
| `fail2ban/jail.local`, `fail2ban/fail2ban.local` | copied to `/etc/fail2ban/` | every start |
| `fail2ban/jail.d/`, `filter.d/`, `action.d/` (`*.conf`, `*.local`) | copied over the packaged files of the same name | every start |
| `fail2ban/jail.conf` | an untouched 1.x default is renamed `.legacy`; an edited one replaces the packaged `jail.conf` | every start |
| `fail2ban/fail2ban.conf` | renamed `.legacy` | every start |
| `fail2ban/fail2ban.sqlite3` | fail2ban's ban history | while running |
| `fail2ban/jail.d/00-webui.local` | the never-ban list and ban settings from the web UI's Bans page | written by the web UI |
| `webui/admins.json` | the admins, with argon2id password hashes and two-factor secrets; `webui/` belongs to the web server's own account, mode 700 | written by the web UI |
| `webui/tls/` | the web UI's certificate: generated when missing, or your own `cert.pem` and `key.pem` | every start, with the web UI on |
| `webui/history.sqlite3` | the permanent history of sign-ins, file operations and bans | while running |
| `audit/webui.log` | every change made in the web UI, with who made it and from where | written by the web UI |
| `browser/tls/` | the file browser's certificate, as `webui/tls/` | every start, with the file browser on |
| `files/logins.json` | file browser sign-ins: web password hashes, two-factor secrets and open sign-in links; root-only | written by the web UI |
| `files/shares.json` | share links, each kept as its token's SHA-256, its file, its end and its password's hash; root-only | written by the file browser |
| `geoip/GeoLite2-Country.mmdb` | MaxMind GeoLite2, used instead of DB-IP Lite while present | downloaded with a MaxMind key |
| `geoip/maxmind.conf` | a MaxMind key saved on the Settings page; root-only | written by the web UI |

Everything else in the container, such as accounts, `/etc/ssh` and the auth log, is rebuilt on each start from `/config`, the environment and the image.

The `users.conf` template written when no account exists:

```text
# Accounts, one per line:
#
#   name:password[:e][:uid[:gid[:dir1,dir2,...[:options]]]]
#
# alice:changeme:1001:100:upload       password login, one writable directory
# bob::1002:100:inbox,outbox            no password: public-key login only
# carol:$y$j9T$...:e:1003               hashed password (see the README)
# dave:pw:1004:100:share:readonly       options: rsync, web, full, readonly,
#                                       uploadonly, perms=, disabled, expires=,
#                                       from=, umask=, group=, manage=,
#                                       noshare, sharedays=, sharepassword
#
# Groups in /config/sshd/groups.conf, name[:gid[:options]], give their
# members defaults: grants add up, limits take the strictest, and what an
# account's own line sets wins, except that every share link limit applies.
#
# Public keys go in /config/userkeys/<name>.pub or /config/userkeys/<name>/*.pub
```
