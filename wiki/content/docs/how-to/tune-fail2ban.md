---
title: How To Tune fail2ban
weight: 6
---

fail2ban reads the auth log and bans an address that fails to log in too often. The built-in jail bans for an hour after 5 failures within 10 minutes. Each new ban of the same address doubles its length, up to one week. Bans are stored in `/config/fail2ban/fail2ban.sqlite3` and restored when the container restarts or is re-created.

A ban blocks every port of the address inside the container's network namespace, so it holds even when sshd listens on another port. It needs `--cap-add NET_ADMIN --cap-add NET_RAW`; without them the log says `fail2ban cannot change firewall rules`.

## Change the ban rules

Write overrides in `/config/fail2ban/jail.local`:

```ini
[DEFAULT]
# Never ban these.
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24
bantime  = 1d
findtime = 30m
maxretry = 3
```

Then restart the container. fail2ban reads `jail.local` after the built-in jail, so these values win. Files in `/config/fail2ban/jail.d/` ending in `.conf` or `.local` are read too. Server settings such as `loglevel` go in `/config/fail2ban/fail2ban.local`.

The configuration is checked with `fail2ban-client --test` at start; a mistake stops the container with fail2ban's message.

## Catch more patterns

The jail uses fail2ban's `sshd` filter in `normal` mode. `aggressive` also counts connections that drop during key exchange and other probes:

```ini
[sshd]
mode = aggressive
```

## See and lift bans

```bash
docker exec sftp fail2ban-client status sshd
docker exec sftp fail2ban-client get sshd banip --with-time
docker exec sftp fail2ban-client set sshd unbanip 203.0.113.7
```

What each returns is in [Commands](../../reference/commands/).

## Your own filters and actions

Files in `/config/fail2ban/filter.d/` and `/config/fail2ban/action.d/` are copied over the packaged ones of the same name at start, so a new filter or action can be referenced from `jail.local`.

## Turn fail2ban off

`-e FAIL2BAN_ENABLED=false` runs sshd without fail2ban. sshd still delays and then refuses an address after repeated failures through its own per-source penalties.

## When every client gets banned

fail2ban bans the address it sees. Behind a reverse proxy, a load balancer or Docker's userland proxy, every client appears with the proxy's address, and one attacker gets everyone banned. See [Security Model](../../explanation/security-model/#client-addresses).
