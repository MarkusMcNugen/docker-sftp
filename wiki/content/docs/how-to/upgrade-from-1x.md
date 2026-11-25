---
title: How To Upgrade From 1.x
weight: 10
---

Point the 2.x image at the same `/config` volume. `users.conf`, host keys, user keys and the fail2ban ban database are read as they are. On its first start the entrypoint deals with the full configuration files 1.x images copied into `/config`:

| File | What happens |
|---|---|
| `sshd/sshd_config`, unchanged since 1.x wrote it | renamed `sshd_config.legacy`; the built-in configuration applies |
| `sshd/sshd_config`, edited | still used as the complete sshd configuration, with a warning |
| `fail2ban/jail.conf`, unchanged | renamed `jail.conf.legacy`; the built-in jail applies |
| `fail2ban/jail.conf`, edited | still used, with a warning |
| `fail2ban/fail2ban.conf` | renamed `fail2ban.conf.legacy`, with a warning |

"Unchanged" means the file's SHA-256 matches one of the defaults 1.x shipped. The log names every file it renames:

```text
entrypoint: /config/sshd/sshd_config is an unmodified 1.x default; the built-in configuration replaces it
entrypoint: renamed /config/sshd/sshd_config to /config/sshd/sshd_config.legacy
```

## Move by hand

- **An edited `sshd_config`.** It works, but the built-in hardening does not apply while it exists. Move your changes into a file in `/config/sshd/sshd_config.d/`, then rename `sshd_config` away. [How To Change sshd Settings](../change-sshd-settings/).
- **Settings from `fail2ban.conf` or an edited `jail.conf`.** Put them in `/config/fail2ban/fail2ban.local` or `/config/fail2ban/jail.local`. [How To Tune fail2ban](../tune-fail2ban/).
- **Keys in `~/.ssh/authorized_keys` inside a jail.** They are not read. Put them in `/config/userkeys/<name>.pub`. [How To Use Public Keys](../use-public-keys/).
- **Capabilities.** Add `--cap-add NET_ADMIN --cap-add NET_RAW`, or fail2ban cannot ban.
- **The fail2ban log.** fail2ban writes to the container log; `/config/fail2ban/fail2ban.log` is no longer written and can be deleted.
