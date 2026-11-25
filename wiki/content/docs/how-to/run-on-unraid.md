---
title: How To Run It On Unraid
weight: 9
---

## Container settings

| Setting | Value |
|---|---|
| Repository | `markusmcnugen/sftp:2` |
| Network type | Bridge |
| Port | host port of your choice to container port `22` |
| Path `/config` | `/mnt/user/appdata/sftp` |
| Extra Parameters (advanced view) | `--cap-add=NET_ADMIN --cap-add=NET_RAW` |
| Variable `TZ` | your time zone, such as `America/New_York` |

Without the extra parameters, fail2ban detects attacks but never blocks them, and the log says so at start.

## Accounts

Create `/mnt/user/appdata/sftp/sshd/users.conf` over SMB or from the terminal. If the container started before the file existed, it wrote a commented template there and stopped; edit it and start the container again.

The `users` group on Unraid is gid 100, which is also the image's default group, so `alice:changeme:1001:100:upload` gives files the group your shares already use.

## Shared folders

Add a Path mapping per folder, with the container path inside the user's home:

| Container path | Host path |
|---|---|
| `/home/alice/upload` | `/mnt/user/uploads/alice` |

The container never changes the owner of an existing directory. Unraid shares belong to `nobody` (uid 99) by default, so either give the account uid 99 (`alice:changeme:99:100`) or make the folder writable by its uid.

## Logs

The container's log icon shows everything: start-up, logins, bans and, with `SFTP_LOG_TRANSFERS=true`, every file operation.
