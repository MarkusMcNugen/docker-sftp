---
title: How To Change sshd Settings
weight: 5
---

## Drop-in files

Put `.conf` files in `/config/sshd/sshd_config.d/`. They are copied into the container at start and read before the built-in configuration. sshd keeps the first value it reads for a keyword, so a drop-in setting replaces the built-in one. Files are read in name order.

The container checks the whole configuration with `sshd -t` before starting and exits with sshd's own message if it is invalid.

## A read-only account

```text
# /config/sshd/sshd_config.d/10-readonly.conf
Match User auditor
    ForceCommand internal-sftp -R
```

`-R` makes the SFTP server refuse every write. Add `-l info` to the line as well if transfer logging is on.

## Only some accounts may log in

```text
# /config/sshd/sshd_config.d/10-allow.conf
AllowUsers alice bob
```

## A banner before login

```text
# /config/sshd/sshd_config.d/10-banner.conf
Banner /config/sshd/banner.txt
```

## Another port

Set `SFTP_PORT=2222`, which also moves the health check. A `Port` line in a drop-in works too.

## The strict crypto policy

`SFTP_CRYPTO_POLICY=strict` removes the plain `hmac-sha2-256` and `hmac-sha2-512` MACs (message authentication codes) from the end of the list, leaving only encrypt-then-MAC ones, which authenticate the encrypted data. Clients that use AES-GCM or ChaCha20-Poly1305 need no MAC and are unaffected. [Security Model](../../explanation/security-model/#cryptography) explains the terms. paramiko, and tools built on it, negotiate plain `hmac-sha2-256` by default and cannot connect under `strict`.

## Settings the environment controls

`SFTP_PORT`, `SFTP_LOG_TRANSFERS`, `SFTP_UMASK` and `SFTP_CRYPTO_POLICY` are passed to sshd on its command line, which takes precedence over every file. If you set your own global `ForceCommand` in a drop-in, `SFTP_LOG_TRANSFERS` and `SFTP_UMASK` replace it; add `-l info` or `-u <umask>` to your own line instead of using those variables. A `ForceCommand` inside a `Match` block is not affected.

## Replacing the whole configuration

A file at `/config/sshd/sshd_config` replaces the built-in configuration entirely, and the log warns that the built-in hardening and the drop-ins no longer apply. Keys from `/config/userkeys` still work. Prefer drop-ins.
