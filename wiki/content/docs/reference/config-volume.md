---
title: The /config Volume
weight: 3
---

| Path | Read or written | When |
|---|---|---|
| `sshd/users.conf` | read; written as a commented template when no account exists anywhere | every start |
| `sshd/keys/ssh_host_ed25519_key`, `ssh_host_rsa_key` (and `.pub`) | generated when missing, then read; private keys set to mode 600 | every start |
| `sshd/sshd_config.d/*.conf` | copied to `/etc/ssh/sshd_config.d/` | every start |
| `sshd/sshd_config` | an untouched 1.x default is renamed `.legacy`; an edited one replaces the built-in configuration | every start |
| `sshd/scripts/*` | executable files and `.sh` files run as root, in name order | every start, after accounts exist |
| `userkeys/<name>.pub`, `userkeys/<name>/*.pub` | public keys, installed for `<name>` | every start |
| `fail2ban/jail.local`, `fail2ban/fail2ban.local` | copied to `/etc/fail2ban/` | every start |
| `fail2ban/jail.d/`, `filter.d/`, `action.d/` (`*.conf`, `*.local`) | copied over the packaged files of the same name | every start |
| `fail2ban/jail.conf` | an untouched 1.x default is renamed `.legacy`; an edited one replaces the packaged `jail.conf` | every start |
| `fail2ban/fail2ban.conf` | renamed `.legacy` | every start |
| `fail2ban/fail2ban.sqlite3` | fail2ban's ban history | while running |

Everything else in the container, such as accounts, `/etc/ssh` and the auth log, is rebuilt on each start from `/config`, the environment and the image.

The `users.conf` template written when no account exists:

```text
# Accounts, one per line:
#
#   name:password[:e][:uid[:gid[:dir1,dir2,...]]]
#
# alice:changeme:1001:100:upload       password login, one writable directory
# bob::1002:100:inbox,outbox            no password: public-key login only
# carol:$y$j9T$...:e:1003               hashed password (see the README)
#
# Public keys go in /config/userkeys/<name>.pub or /config/userkeys/<name>/*.pub
```
