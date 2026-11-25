---
title: Environment Variables
weight: 1
---

Every variable the container reads. All are optional. A value the image does not accept stops the container at start with a message naming the variable, before anything is created.

| Variable | Default | Accepted values | Effect |
|---|---|---|---|
| `SFTP_USERS` | empty | account lines separated by spaces | Accounts, read after `users.conf`, the secrets file and the arguments |
| `SFTP_USERS_FILE` | empty | a path inside the container | A file of account lines, such as `/run/secrets/sftp_users`; read after `users.conf`. An unreadable file stops the container |
| `SFTP_PORT` | `22` | 1 to 65535 | The port sshd listens on inside the container; the health check follows it |
| `SFTP_LOG_TRANSFERS` | `false` | `true`, `false`, `yes`, `no`, `on`, `off`, `1`, `0` | Log every file operation ([How To Log Transfers](../../how-to/log-transfers/)) |
| `SFTP_UMASK` | empty | three or four octal digits, such as `002` or `0027` | The umask, the permission bits removed from files and directories users create; empty keeps `022`, which removes write permission for group and others |
| `SFTP_CRYPTO_POLICY` | `modern` | `modern`, `strict` | `strict` drops the plain `hmac-sha2-256` and `hmac-sha2-512` MACs ([Built-in Settings](../built-in-settings/)) |
| `SFTP_AUTH_LOG_MAX_BYTES` | `10485760` | a whole number of bytes; `0` for no cap | The size at which `/var/log/auth.log` is copied to `auth.log.1` and emptied. Read every five seconds |
| `FAIL2BAN_ENABLED` | `true` | as `SFTP_LOG_TRANSFERS` | `false` runs without fail2ban |
| `TZ` | `UTC` | a zone name such as `Europe/Berlin` | The time zone of log timestamps |

`SFTP_PORT`, `SFTP_LOG_TRANSFERS`, `SFTP_UMASK` and `SFTP_CRYPTO_POLICY` reach sshd as command-line options, which take precedence over the sshd configuration files ([How To Change sshd Settings](../../how-to/change-sshd-settings/#settings-the-environment-controls)).
