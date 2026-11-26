---
title: How To Run It On Unraid
weight: 9
---

## Install the template

In **Apps**, Community Applications, search for **sftp** by MarkusMcNugen and install it. Without Community Applications, add `https://github.com/MarkusMcNugen/docker-templates` under **Docker**, **Template repositories**, then **Add Container** and pick **sftp**.

The template fills in:

| Setting | Value |
|---|---|
| Repository | `markusmcnugen/sftp:2` |
| Network type | Bridge |
| SFTP port | host port `2222` to container port `22`; Unraid's own SSH server listens on 22 |
| Admin web UI port | `8443` |
| File browser port | `8444`, used once the file browser is on |
| Path `/config` | `/mnt/user/appdata/sftp` |
| Extra Parameters | `--cap-add=NET_ADMIN --cap-add=NET_RAW` |
| Admin web UI | `true` |
| File browser | `false` |

Without the extra parameters, fail2ban detects attacks but never blocks them, and the log says so at start. Unraid passes its time zone to the container by itself.

## Sign in to the admin web UI

The container's menu on the **Docker** tab has **WebUI**, which opens `https://<server>:8443/`. The certificate is self-signed, so the browser warns once; the log prints its SHA-256 fingerprint to compare.

On first start the log, the container's log icon, prints a setup link for the first admin that works once, for one hour. Open it, choose a name and a password, and you are signed in ([How To Use The Admin Web UI](../use-the-web-ui/)).

Change the server's settings on the web UI's **Settings** page rather than adding variables to the template. Unraid passes every variable in the template, empty ones too, and a variable set in the environment wins over the Settings page, so an added variable locks that setting even when it is empty.

## Accounts

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Open **Accounts** and choose **New account** ([How To Add And Change Users](../add-users/)).
{{< /tab >}}
{{< tab name="Command line" >}}
Create `/mnt/user/appdata/sftp/sshd/users.conf` over SMB or from the terminal. If the container started before the file existed, it wrote a commented template there and stopped; edit it and start the container again.
{{< /tab >}}
{{< /tabs >}}

The `users` group on Unraid is gid 100, which is also the image's default group, so `alice:changeme:1001:100:upload` gives files the group your shares already use.

## Shared folders

Add a Path to the container for each folder, with the container path inside the user's home:

| Container path | Host path |
|---|---|
| `/home/alice/upload` | `/mnt/user/uploads/alice` |

The container never changes the owner of an existing folder. Unraid shares belong to `nobody` (uid 99) by default, so either give the account uid 99 (`alice:changeme:99:100`, or **User ID** `99` on the account's page) or make the folder writable by its uid.

## Logs

The container's log icon shows everything: start-up, logins, bans and, with transfer logging on, every file operation. The web UI's **Logs** page shows the same log, and **Activity** keeps the history of sign-ins and file operations.
