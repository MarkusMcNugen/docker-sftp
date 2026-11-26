---
title: How To Share Host Directories
weight: 4
---

Each user is jailed in `/home/<name>`, which must belong to root because sshd refuses to chroot (change its root directory) into anything else. Users therefore write into folders inside their home, and those are where host directories are mounted. Mounts are part of how the container runs, so they are set in `docker run` or Compose, never in the web UI.

## Mount a host directory for one user

```bash
mkdir -p /srv/sftp/alice
chown 1001:100 /srv/sftp/alice

docker run -d --name sftp --cap-add NET_ADMIN --cap-add NET_RAW -p 2222:22 \
  -v /srv/sftp/config:/config \
  -v /srv/sftp/alice:/home/alice/upload \
  markusmcnugen/sftp alice:changeme:1001:100:upload
```

The container never changes the owner of a folder that already exists, so the host directory must belong to the user's uid, here `1001`. If it does not, the user can see it but not write to it.

The account's writable directories name the folders in its jail, `upload` here. In the web UI they are **Writable directories** on the account's page, one per line; on the command line, the fifth field of its line.

![The Account section of an account, with its writable directories](/screenshots/account-details.png)

## Read-only for the user

Mount it read-only:

```bash
-v /srv/reports:/home/alice/reports:ro
```

For an account that may read but never write anywhere, make it read-only ([How To Set Account Permissions](../set-account-permissions/)).

## One folder for several users

Mount the same host directory into each jail and give it a group they share:

```bash
chown -R :2000 /srv/shared && chmod -R g+rwX /srv/shared
```

```bash
-v /srv/shared:/home/alice/shared -v /srv/shared:/home/bob/shared
```

Then put both accounts in that group, and let new files be group-writable with a umask of `002`:

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
On each account's page, set **Group ID** to `2000`, or put the accounts in a group whose **Files' group** is `2000` ([How To Group Accounts](../group-accounts/)). On the **Settings** page, set **Permissions for new files** to `002`.
{{< /tab >}}
{{< tab name="Command line" >}}
```text
alice:pw1:1001:2000:shared
bob:pw2:1002:2000:shared
```

and add `-e SFTP_UMASK=002`, or `SFTP_UMASK=002` in `/config/sshd/settings.conf`.
{{< /tab >}}
{{< /tabs >}}

## The home directory itself

When `/home/<name>` already exists with another owner or with group or other write permission, the entrypoint makes it root-owned and removes those write bits, and logs a warning. Mounting a host directory directly at `/home/<name>` therefore changes that host directory's owner to root.
