---
title: How To Share Host Directories
weight: 4
---

Each user is jailed in `/home/<name>`, which must belong to root because sshd refuses to chroot (change its root directory) into anything else. Users therefore write into subdirectories of their home, and those are where host directories are mounted.

## Mount a host directory for one user

```bash
mkdir -p /srv/sftp/alice
chown 1001:100 /srv/sftp/alice

docker run -d --name sftp --cap-add NET_ADMIN --cap-add NET_RAW -p 2222:22 \
  -v /srv/sftp/config:/config \
  -v /srv/sftp/alice:/home/alice/upload \
  markusmcnugen/sftp alice:changeme:1001:100
```

The container never changes the owner of a directory that already exists, so the host directory must belong to the user's uid, here `1001`. If it does not, the user can see it but not write to it.

## Read-only for the user

Mount it read-only:

```bash
-v /srv/reports:/home/alice/reports:ro
```

For a whole account that may read but never write, see [How To Change sshd Settings](../change-sshd-settings/).

## One folder for several users

Mount the same host directory into each jail and give it a group they share:

```bash
chown -R :2000 /srv/shared && chmod -R g+rwX /srv/shared
```

```text
alice:pw1:1001:2000
bob:pw2:1002:2000
```

```bash
-v /srv/shared:/home/alice/shared -v /srv/shared:/home/bob/shared
```

New files are group-writable only with a umask that allows it, so add `-e SFTP_UMASK=002`.

## The home directory itself

When `/home/<name>` already exists with another owner or with group or other write permission, the entrypoint makes it root-owned and removes those write bits, and logs a warning. Mounting a host directory directly at `/home/<name>` therefore changes that host directory's owner to root.
