---
title: How To Apply Changes Without A Restart
weight: 4
---

After editing anything in `/config`, apply it to the running server:

```console
$ docker exec sftp entrypoint apply
... entrypoint: user ben: created (uid 1303, gid 100)
... entrypoint: applied; sshd's listener restarted and open sessions kept
```

`entrypoint apply` does what a start does, with the environment and arguments the container started with: it validates every account line and setting, reconciles the accounts, keys and jails, reruns the startup scripts, and checks the sshd and fail2ban configuration. It then restarts sshd's listener and reloads fail2ban, and rsyslog when transfer logging needs new sockets.

Open sessions stay connected, except those of accounts that were removed, disabled or expired. A mistake stops the apply with the same message a start would print, and the server keeps running as it was.

## Settings in /config

`/config/sshd/settings.conf` holds settings as `NAME=value` lines, which the web UI writes and `apply` reads:

```text
SFTP_PORT=2222
SFTP_UMASK=002
```

It accepts `SFTP_PORT`, `SFTP_LOG_TRANSFERS`, `SFTP_UMASK`, `SFTP_CRYPTO_POLICY` and `SFTP_AUTH_LOG_MAX_BYTES`. A setting in the container's environment wins over the file. A changed `SFTP_PORT` needs the published port changed too.
