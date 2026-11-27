---
title: SFTP Wiki
toc: false
---

A hardened OpenSSH SFTP server in one container, with an optional admin web UI and file browser behind two-factor sign-in. Every account is jailed in its own home directory, fail2ban bans addresses that keep guessing passwords, and all configuration lives in one `/config` volume.

{{< cards >}}
  {{< card link="docs/tutorials/" title="Tutorials" subtitle="Your first server, in the web UI or on the command line: two accounts, a password login, a key login and a shared folder." icon="academic-cap" >}}
  {{< card link="docs/how-to/" title="How-to" subtitle="One task per page, in the web UI and on the command line: users, keys, the file browser, bans, countries, Unraid, upgrading." icon="cog" >}}
  {{< card link="docs/explanation/" title="Explanation" subtitle="How the container starts and runs, and what each security measure protects against." icon="book-open" >}}
  {{< card link="docs/reference/" title="Reference" subtitle="Environment variables, users.conf, the /config volume, commands, settings, log lines." icon="document-text" >}}
{{< /cards >}}

## Quick links

- **New here?** [Your First Server](docs/tutorials/first-server/), from an empty folder to a working upload.
- **Managing it in a browser?** [How To Use The Admin Web UI](docs/how-to/use-the-web-ui/) and [How To Use The File Browser](docs/how-to/use-the-file-browser/).
- **Adding people?** [How To Add And Change Users](docs/how-to/add-users/) and [users.conf](docs/reference/users-conf/).
- **Something failed?** [How To Fix A Failure](docs/how-to/fix-a-failure/), keyed by the message you see.
- **Coming from 1.x?** [How To Upgrade From 1.x](docs/how-to/upgrade-from-1x/).

## Wiki contents

### Tutorials

1. [Your First Server](docs/tutorials/first-server/) - start the container, add two accounts, log in with a password and a key, share a host folder, in the web UI or on the command line.

### How-to

- [How To Add And Change Users](docs/how-to/add-users/) - users.conf, SFTP_USERS, a secrets file, and what a restart changes.
- [How To Use Hashed Passwords](docs/how-to/use-hashed-passwords/) - mkpasswd in the image, the :e marker, and Compose escaping.
- [How To Set Account Permissions](docs/how-to/set-account-permissions/) - read-only, upload-only or a custom set; disabled accounts, end dates, allowed networks and a umask.
- [How To Use Public Keys](docs/how-to/use-public-keys/) - one or many keys per user, where they are installed, and revoking one.
- [How To Apply Changes Without A Restart](docs/how-to/apply-changes-live/) - entrypoint apply, settings in /config, and the sessions that stay open.
- [How To Share Host Directories](docs/how-to/share-host-directories/) - bind mounts in a jail, ownership, read-only mounts, folders several users share.
- [How To Change sshd Settings](docs/how-to/change-sshd-settings/) - drop-in files, a read-only account, another port, the strict crypto policy.
- [How To Tune fail2ban](docs/how-to/tune-fail2ban/) - ban rules, trusted addresses, unbanning, your own filters.
- [How To Log Transfers](docs/how-to/log-transfers/) - a log line for every upload, download, rename and delete.
- [How To Allow rsync](docs/how-to/allow-rsync/) - rsync over SSH for chosen accounts, inside their jails.
- [How To Harden The Container](docs/how-to/harden-the-container/) - the minimal capability set, no-new-privileges, log rotation.
- [How To Run It On Unraid](docs/how-to/run-on-unraid/) - template settings, extra parameters, the file browser, share permissions.
- [How To Upgrade From 1.x](docs/how-to/upgrade-from-1x/) - what happens to an existing /config and what to move by hand.
- [How To Build And Test The Image](docs/how-to/build-and-test/) - building, the integration suite, running some scenarios only.
- [How To Fix A Failure](docs/how-to/fix-a-failure/) - every failure, keyed by the message you see.
- [How To Use The Admin Web UI](docs/how-to/use-the-web-ui/) - turning it on, the first admin, two-factor, more admins, the audit log, a reverse proxy.
- [How To Use The File Browser](docs/how-to/use-the-file-browser/) - turning it on, letting an account in, managers, and share links.
- [How To Group Accounts](docs/how-to/group-accounts/) - groups.conf, the defaults members get, and accounts that manage others.
- [How To Block Countries](docs/how-to/block-countries/) - dropping chosen countries at the firewall, with DB-IP Lite or MaxMind GeoLite2.
- [How To Hold Unusual Sign-ins](docs/how-to/hold-unusual-sign-ins/) - approval for sign-ins from new places or impossible travel, and lockdowns during a password spray.

### Explanation

- [How The Container Works](docs/explanation/how-the-container-works/) - processes, start-up order, reconciliation, logs, the health check.
- [Security Model](docs/explanation/security-model/) - the jail, keys outside it, cryptography, brute force, client addresses, capabilities.

### Reference

- [Environment Variables](docs/reference/environment-variables/) - every variable, its default, its accepted values.
- [users.conf](docs/reference/users-conf/) - the account line grammar and what the entrypoint does with each account.
- [The /config Volume](docs/reference/config-volume/) - every path read or written, and when.
- [Commands](docs/reference/commands/) - the entrypoint, healthcheck, mkpasswd and fail2ban-client, with their output.
- [Built-in Settings](docs/reference/built-in-settings/) - the effective sshd, fail2ban and account settings.
- [Log Messages](docs/reference/log-messages/) - every source in the log, with real lines.

## License

MIT - see [LICENSE.txt](https://github.com/MarkusMcNugen/docker-sftp/blob/main/LICENSE.txt) on the repository.
