---
title: How To Log Transfers
weight: 7
---

With transfer logging on, every file operation over SFTP is logged and kept in the history: uploads, downloads, renames, deletions and new folders. Logins are logged either way.

## Turn it on

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Open **Settings**, set **Log every file operation** to on in the **SFTP server** card, and save. It applies at once.
{{< /tab >}}
{{< tab name="Command line" >}}
Add `SFTP_LOG_TRANSFERS=true` to `/config/sshd/settings.conf` and run `docker exec sftp entrypoint apply`, or set it in the container's environment and restart.
{{< /tab >}}
{{< /tabs >}}

## See the transfers

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
The **Activity** page shows who did what, as it happens. **People** gives a card for each account active in the last 24 hours with its latest operations and totals; **Log** lists every sign-in and file operation, filtered by account, kind and time.

![The Activity page](/screenshots/activity.png)

What the file browser does is recorded there too, with the person who did it and their address.
{{< /tab >}}
{{< tab name="Command line" >}}
Every file operation appears in `docker logs`:

```text
internal-sftp[110]: session opened for local user alice from [10.89.0.3]
internal-sftp[110]: open "/upload/blob" flags WRITE,CREATE,TRUNCATE mode 0644
internal-sftp[110]: close "/upload/blob" bytes read 0 written 4096
internal-sftp[110]: posix-rename old "/upload/blob" new "/upload/blob2"
internal-sftp[110]: remove name "/upload/blob2"
internal-sftp[110]: session closed for local user alice from [10.89.0.3]
```

Paths are as the user sees them, relative to their jail. The same lines also go to the internal auth log, and from there into `/config/webui/history.sqlite3` when the web UI is on.
{{< /tab >}}
{{< /tabs >}}

## How it works

A user's SFTP session runs inside the jail, where the normal log socket `/dev/log` does not exist. The entrypoint creates `/home/<name>/dev` and has rsyslog listen on a socket there, which the session sees as `/dev/log`. The `dev` directory is root-owned and visible to the user, who cannot write to it.

The setting adds `-l info` to the SFTP server's command line. If you set your own `ForceCommand` in a drop-in, add `-l info` to it yourself.

## When transfers are not logged

The entrypoint checks each socket and warns:

```text
warning: rsyslogd did not create /home/alice/dev/log, so transfers in that chroot are not logged.
```

This happens when a security policy on the host confines rsyslogd. Ubuntu ships an AppArmor profile for `/usr/sbin/rsyslogd`, and it also applies to the container's rsyslogd when the container runs without a profile of its own, as rootless Podman containers do. Docker gives every container its own profile and Unraid has no AppArmor, so neither should block it. Logins, bans and the auth log work either way.

The entrypoint also skips a user whose `/home/<name>/dev` already exists and is not owned by root, such as an upload directory named `dev`, and warns about it.
