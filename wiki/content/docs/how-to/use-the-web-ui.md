---
title: How To Use The Admin Web UI
weight: 13
---

The image includes an admin web UI for accounts, groups, keys, permissions, settings, bans, country rules, the activity history, logs and the audit log. It is off until you turn it on, and changes made in it apply at once, without a restart.

[How To Group Accounts](../group-accounts/), [How To Block Countries](../block-countries/) and [How To Use The File Browser](../use-the-file-browser/) cover the pages for those.

## Turn it on

```yaml
services:
  sftp:
    image: markusmcnugen/sftp:2
    ports:
      - "2222:22"
      - "8443:8443"
    environment:
      WEBUI_ENABLED: "true"
    volumes:
      - ./config:/config
```

The UI serves HTTPS only, on `WEBUI_PORT` (8443). On first start it creates a self-signed certificate in `/config/webui/tls/` and prints its SHA-256 fingerprint in the log, which you can compare with what your browser shows. To use your own certificate, put `cert.pem` and `key.pem` there before starting.

## Create the first admin

With no admin yet, the log prints a link that works once, for one hour:

```console
$ docker logs sftp 2>&1 | grep setup
... sftp-webui: no admin exists yet; within one hour, open https://<this server>:8443/setup?token=... to create one
```

Open it, choose a name and a password of at least 12 characters, and you are signed in as a full admin. Then open **Your sign-in** and set up two-factor sign-in with an authenticator app.

If nobody uses the link within the hour, opening the login page prints a new one.

## Add admins

Under **Admins**, an invite creates a link that works once, for 24 hours; send it over a channel you trust. The new admin chooses their own password. Roles:

| Role | Can |
|---|---|
| full | everything |
| read-only | view every page; change only their own password and two-factor sign-in |

The last full admin cannot be removed or demoted.

## Supply admins from a file

For a scripted deployment, put admins in a file, such as a Docker secret, one per line as `name:role:hash`, and name it in `WEBUI_ADMIN_FILE`:

```console
$ docker run --rm -i markusmcnugen/sftp:2 sftp-webui hash-password <<<'a long passphrase here'
$argon2id$v=19$m=65536,t=3,p=1$...
```

```text
alice:full:$argon2id$v=19$m=65536,t=3,p=1$...
```

Admins from the file cannot be changed in the UI, except for their two-factor sign-in. With the file set, no setup link is printed.

## Behind a reverse proxy

A proxy that serves HTTPS can talk plain HTTP to the container:

```yaml
    environment:
      WEBUI_ENABLED: "true"
      WEBUI_PLAIN_HTTP: "true"
      WEBUI_TRUSTED_PROXIES: "172.18.0.2"
```

Plain HTTP is accepted only from the addresses in `WEBUI_TRUSTED_PROXIES`, and `X-Forwarded-For` is read only from them. The browser must still reach the proxy over HTTPS: the session cookie is marked `Secure`. Keep the `Host` header (`proxy_set_header Host $host` in nginx).

## Skip the code on your own network

`WEBUI_TRUSTED_NETWORKS` lists networks, such as `192.168.1.0/24`, from which admins sign in without a two-factor code. The password is still needed. It is empty, and so off, by default.

## Lost access

If every admin has lost their password or their phone, remove the admin store and restart; a new setup link is printed:

```console
$ docker exec sftp rm /config/webui/admins.json
$ docker restart sftp
```

## What it protects against

Failed sign-ins are throttled: five from one address in 15 minutes lock that address out for 15 minutes, at most 30 failures a minute are evaluated across all addresses, and fail2ban's `sftp-webui` jail bans the address on every port. [Security Model](../../explanation/security-model/#the-admin-web-ui) explains the rest.
