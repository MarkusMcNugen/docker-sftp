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
| `SFTP_AUTH_LOG_MAX_BYTES` | `10485760` (10 MiB) | a whole number, in B; `0` for no cap | The size at which `/var/log/auth.log` is copied to `auth.log.1` and emptied. Read every five seconds |
| `SFTP_RSYNC_USERS` | empty | account names separated by spaces, or `*` | Accounts allowed rsync over SSH, besides those whose line ends in `:rsync`; a name that is not an account stops the container ([How To Allow rsync](../../how-to/allow-rsync/)) |
| `FAIL2BAN_ENABLED` | `true` | as `SFTP_LOG_TRANSFERS` | `false` runs without fail2ban |
| `TZ` | `UTC` | a zone name such as `Europe/Berlin` | The time zone of log timestamps |
| `WEBUI_ENABLED` | `false` | as `SFTP_LOG_TRANSFERS` | Runs the admin web UI ([How To Use The Admin Web UI](../../how-to/use-the-web-ui/)) |
| `WEBUI_PORT` | `8443` | 1024 to 65535, not an sshd port | The web UI's port inside the container |
| `WEBUI_PLAIN_HTTP` | `false` | as `SFTP_LOG_TRANSFERS` | Plain HTTP for a reverse proxy; needs `WEBUI_TRUSTED_PROXIES` |
| `WEBUI_TRUSTED_PROXIES` | empty | addresses or networks, separated by spaces or commas | Proxies allowed to connect in plain HTTP and to send `X-Forwarded-For` |
| `WEBUI_TRUSTED_NETWORKS` | empty | as `WEBUI_TRUSTED_PROXIES` | Networks from which admins and file browser users sign in without a two-factor code, and which the country rules always let in |
| `WEBUI_ADMIN_FILE` | empty | a path inside the container | Admins as `name:role:hash` lines, made with `sftp-webui hash-password` |
| `WEBUI_FILES_ENABLED` | `false` | as `SFTP_LOG_TRANSFERS`; needs `WEBUI_ENABLED` | Runs the file browser ([How To Use The File Browser](../../how-to/use-the-file-browser/)) |
| `WEBUI_FILES_PORT` | `8444` | 1024 to 65535, not `WEBUI_PORT` or 2299 | The file browser's port inside the container; 2299 is its own sshd's, on loopback |
| `FILES_SHARE` | `true` | as `SFTP_LOG_TRANSFERS` | Whether file browser users may share a file by link |
| `FILES_SHARE_DAYS` | `7` | 1 to 999999999 | The share link length the share dialog chooses first |
| `FILES_SHARE_MAX_DAYS` | `30` | 1 to 999999999 | The longest a share link may last, in days |
| `FILES_SHARE_PASSWORD` | `false` | as `SFTP_LOG_TRANSFERS` | Every share link needs a password |
| `SFTP_COUNTRY_RULE` | `off` | `off`, `block`, `allow` | Drops new connections from the listed countries (`block`) or from every other one (`allow`) ([How To Block Countries](../../how-to/block-countries/)) |
| `SFTP_COUNTRIES` | `CN IN BR RU VN` | two-letter country codes, separated by spaces or commas | The countries the rule lists; `allow` needs at least one |
| `MAXMIND_ACCOUNT_ID` | empty | a MaxMind account ID; set both or neither | With `MAXMIND_LICENSE_KEY`, MaxMind GeoLite2 replaces DB-IP Lite as the country database |
| `MAXMIND_LICENSE_KEY` | empty | a MaxMind license key | See `MAXMIND_ACCOUNT_ID` |

`SFTP_PORT`, `SFTP_LOG_TRANSFERS`, `SFTP_UMASK`, `SFTP_CRYPTO_POLICY`, `SFTP_AUTH_LOG_MAX_BYTES`, `SFTP_COUNTRY_RULE`, `SFTP_COUNTRIES` and the four `FILES_SHARE` settings can also be set in `/config/sshd/settings.conf`, which the web UI writes; a variable set in the environment wins ([How To Apply Changes Without A Restart](../../how-to/apply-changes-live/#settings-in-config)).

`SFTP_PORT`, `SFTP_LOG_TRANSFERS`, `SFTP_UMASK` and `SFTP_CRYPTO_POLICY` reach sshd as command-line options, which take precedence over the sshd configuration files ([How To Change sshd Settings](../../how-to/change-sshd-settings/#settings-the-environment-controls)).
