---
title: How To Use The File Browser
weight: 14
---

The file browser lets account holders work with their files in a web browser: upload, download, preview, search and share. It runs beside the admin web UI on its own port, and each account is let in by an admin.

## Turn it on

```yaml
services:
  sftp:
    image: markusmcnugen/sftp:2
    ports:
      - "2222:22"
      - "8443:8443"
      - "8444:8444"
    environment:
      WEBUI_ENABLED: "true"
      WEBUI_FILES_ENABLED: "true"
    volumes:
      - ./config:/config
```

The file browser needs the admin web UI, where admins let accounts in. It serves HTTPS on `WEBUI_FILES_PORT` (8444), a port from 1024 to 65535. On first start it creates a self-signed certificate in `/config/browser/tls/` and prints its SHA-256 fingerprint in the log; to use your own certificate, put `cert.pem` and `key.pem` there before starting. `WEBUI_PLAIN_HTTP`, `WEBUI_TRUSTED_PROXIES` and `WEBUI_TRUSTED_NETWORKS` apply to it as they do to the admin web UI.

## Let an account in

1. In the admin web UI, open the account and turn on **File browser**, or turn on **Members may use the file browser** for one of its groups. In `users.conf` this is the `web` option.
2. On the account's page, **Make a sign-in link**. The link works once, for 24 hours; send it to the account holder over a channel you trust.
3. The holder opens it, chooses a web password of at least 12 characters, and adds the code from an authenticator app.

The web password is separate from the account's SFTP password, so an account that logs in with a key only can use the file browser too. Every sign-in asks for the password and a code from the app, except from `WEBUI_TRUSTED_NETWORKS`, and each code works once. A session ends after half an hour unused, or twelve hours in all.

If the holder loses the password or the phone, **Reset sign-in** on the account's page and make a new link.

## What it does

The page has three panes: the folder tree, the files of the open folder as a list or a grid, and the details of the chosen file.

- Upload by dragging files or folders onto the page. Uploads stream to disk with no size limit, and an upload that stopped goes on from where the server's copy ends.
- Download a file, or a folder or a selection as a zip file.
- Preview pictures, PDFs, audio, video and text.
- Rename, move, copy and delete one item or a selection, and make folders.
- Search by name in a folder and every folder below it.
- See in a file's details who added it, from where and how, and everything done with it since.
- Open a zip, tar, tar.gz or tgz archive to list its entries, download one, or unpack it beside itself.

Each account can do in the file browser exactly what it can do over SFTP: the file browser works through SFTP, with the account's permissions and jail, and every operation goes into the same history and transfer log.

## Open the files of other accounts

An account with `manage=name` on its line, or `manage=@group` for every member of a group, sees those accounts under **You manage** and can open their files, with each account's own permissions. What it does there is logged under both names. **Can open the files of** on the account's page sets this.

## Share a file by link

Choose a file, then **Share**. Pick how long the link lasts and, if you like, a password, and copy the link: it is shown once. The link works for one download, then stops; **Links you shared** lists every link you made, used or waiting, and ends one early.

The part of the link after the `#` is the key to the file. Browsers do not send it when they open the page, so it is in no address a server or a proxy logs; the page sends it in the body of its own requests. The server keeps only its SHA-256, so a link cannot be recovered from the server. Send the password, when there is one, apart from the link. A wrong password counts toward the address's sign-in lockout and fail2ban.

The admin web UI's **Settings** page sets what links may do:

| Setting | Default | Effect |
|---|---|---|
| `FILES_SHARE` | `true` | `false` turns share links off for everyone |
| `FILES_SHARE_DAYS` | `7` | The length the share dialog chooses first |
| `FILES_SHARE_MAX_DAYS` | `30` | The longest a link may last, in days |
| `FILES_SHARE_PASSWORD` | `false` | `true` makes every link need a password |

A group or an account can only tighten that policy, with `noshare`, `sharedays=N` and `sharepassword` on its line, or the matching controls on its page. A link to a file obeys the limits of the account whose file it is and of the account making it.
