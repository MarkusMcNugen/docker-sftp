---
title: How The Container Works
weight: 1
---

## Processes

```text
tini                      process 1: forwards signals, reaps exited processes
└─ entrypoint (bash)      builds the configuration, then supervises
   ├─ rsyslogd            receives log messages on /dev/log
   ├─ auth-log rotation   a loop in the entrypoint, when the cap is on
   ├─ GeoLite2 refresh    a loop in the entrypoint, every six hours
   ├─ fail2ban-server     reads /var/log/auth.log, adds firewall rules
   ├─ sshd                the SFTP server
   ├─ sshd (loopback)     the file browser's SFTP server, on 127.0.0.1:2299
   ├─ sftp-helper         as root: the web UI's requests, and the history
   ├─ sftp-webui serve    the admin web UI, as the user sftp-webui
   └─ sftp-webui files    the file browser, as the user sftp-files
```

The last four run only with the web UI on, and the loopback sshd and the file browser only with the file browser on.

The entrypoint waits for any of its children to exit. When one does, it stops the others and exits non-zero, so Docker's restart policy brings back a complete server rather than one with a service missing. On `docker stop`, tini passes the signal to the entrypoint, which stops sshd and fail2ban first and rsyslog last, so their shutdown is still logged. A stop takes under a second.

## Start-up order

1. **Restore the image's configuration.** `/etc/ssh/sshd_config`, `/etc/fail2ban` and the key directory are replaced by pristine copies from the image, so a file removed from `/config` since the last start is gone from the container too.
2. **Collect and validate.** Account lines are read from every source and checked, then every environment variable. Nothing has been created yet, so a mistake stops the container with no side effects.
3. **sshd configuration.** Files from `/config/sshd/sshd_config.d/` are installed, and 1.x files are handled ([How To Upgrade From 1.x](../../how-to/upgrade-from-1x/)).
4. **Host keys.** Missing ones are generated in `/config/sshd/keys`; every key's fingerprint is logged.
5. **Accounts.** Accounts that are no longer configured are deleted. Every configured account is created or brought up to date: uid, gid, password, home directory, directories, keys.
6. **Startup scripts** in `/config/sshd/scripts/` run.
7. **Checks.** `sshd -t` validates the sshd configuration, and the ports it will listen on are recorded for the health check.
8. **Country rules**, when on, are loaded into nftables ([How To Block Countries](../../how-to/block-countries/)).
9. **Transfer logging**, when on, prepares a log socket in each jail.
10. **fail2ban.** Files from `/config/fail2ban/` are installed, `fail2ban-client --test` validates them, and the firewall backend is chosen.
11. **Services start**: rsyslog, the loops, fail2ban, sshd, then the file browser's sshd and the web UI's helper and servers when they are on.

## Accounts are reconciled

Every account the entrypoint creates is marked `sftp-managed` in its account entry and added to the `sftpusers` group. On each start the entrypoint compares the marked accounts with the configuration, so a restart, not only a new container, applies a changed password, a removed key or a removed account. An account it did not create, such as `root`, can never be taken over: a line naming one stops the container.

## Where logs go

sshd sends its messages to rsyslog through `/dev/log`. rsyslog writes every message to the container's output, where `docker logs` shows it, and writes auth messages also to `/var/log/auth.log`, which fail2ban reads. fail2ban writes its own messages to the container's output directly.

`/var/log/auth.log` is capped at `SFTP_AUTH_LOG_MAX_BYTES` (10 MiB by default): when it reaches the cap, the rotation loop copies it to `auth.log.1` and empties it. rsyslog appends, so it carries on at the start of the emptied file without being told. Rate limiting is off in rsyslog, so no failed login is dropped during an attack.

## The health check

`healthcheck` reads `/proc/net/tcp` and `/proc/net/tcp6` for a listening socket on each recorded port, and checks that fail2ban's socket and process exist. It opens no connection, so it adds nothing to the auth log fail2ban reads. Docker runs it every 30 seconds.

## The firewall backend

fail2ban bans with iptables. At start the entrypoint creates and deletes a test chain with the nftables-based iptables, and falls back to the legacy one if that fails. Bans apply in the container's own network namespace, never on the host.

The country rules are an nftables table of their own, `inet sftp_countries`, in the same namespace. The root helper loads it in batches: each list of networks goes into sets that no rule reads yet, at most 4,000 elements to a set, and one transaction then points the rules at them and the sets they read before are deleted.
