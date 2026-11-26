---
title: How To Change sshd Settings
weight: 5
---

The common settings, the port, transfer logging, the umask, the crypto policy and the login log's size, are on the admin web UI's **Settings** page and in `/config/sshd/settings.conf`. Anything else sshd supports goes in drop-in files.

## The common settings

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Open **Settings**, change the **SFTP server** card, and save. The change applies at once, and open sessions stay connected.

![The SFTP server card on the Settings page](/screenshots/settings-server.png)

A setting the container's environment sets is shown under **Set in the environment** and cannot be changed here, because the environment wins.
{{< /tab >}}
{{< tab name="Command line" >}}
Put `NAME=value` lines in `/config/sshd/settings.conf`, then run `docker exec sftp entrypoint apply`:

```text
SFTP_PORT=2222
SFTP_LOG_TRANSFERS=true
SFTP_UMASK=002
SFTP_CRYPTO_POLICY=strict
```

Or set the same names in the container's environment, which wins over the file. [Environment Variables](../../reference/environment-variables/) lists them.
{{< /tab >}}
{{< /tabs >}}

### Another port

**Port** on the Settings page, or `SFTP_PORT=2222`, moves sshd and the health check. A `Port` line in a drop-in works too.

### The strict crypto policy

**Encryption policy** set to strict, or `SFTP_CRYPTO_POLICY=strict`, removes the plain `hmac-sha2-256` and `hmac-sha2-512` MACs (message authentication codes) from the end of the list, leaving only encrypt-then-MAC ones, which authenticate the encrypted data. Clients that use AES-GCM or ChaCha20-Poly1305 need no MAC and are unaffected. [Security Model](../../explanation/security-model/#cryptography) explains the terms. paramiko, and tools built on it, negotiate plain `hmac-sha2-256` by default and cannot connect under `strict`.

## Drop-in files

Put `.conf` files in `/config/sshd/sshd_config.d/`. They are copied into the container and read before the built-in configuration. sshd keeps the first value it reads for a keyword, so a drop-in setting replaces the built-in one. Files are read in name order.

The container checks the whole configuration with `sshd -t` and refuses it with sshd's own message if it is invalid: at start the container exits, and `entrypoint apply` keeps the running configuration.

### Only some accounts may log in

```text
# /config/sshd/sshd_config.d/10-allow.conf
AllowUsers alice bob
```

### A banner before login

```text
# /config/sshd/sshd_config.d/10-banner.conf
Banner /config/sshd/banner.txt
```

### A read-only account

Use the account's read-only permissions rather than a drop-in ([How To Set Account Permissions](../set-account-permissions/)).

## Settings sshd gets on its command line

`SFTP_PORT`, `SFTP_LOG_TRANSFERS`, `SFTP_UMASK` and `SFTP_CRYPTO_POLICY` are passed to sshd on its command line, which takes precedence over every file. If you set your own global `ForceCommand` in a drop-in, transfer logging and the umask replace it; add `-l info` or `-u <umask>` to your own line instead. A `ForceCommand` inside a `Match` block is not affected.

## Replacing the whole configuration

A file at `/config/sshd/sshd_config` replaces the built-in configuration entirely, and the log warns that the built-in hardening and the drop-ins no longer apply. Keys from `/config/userkeys` still work. Prefer drop-ins.
