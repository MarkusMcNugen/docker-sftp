---
title: users.conf
weight: 2
---

## Grammar

```text
name:password[:e][:uid[:gid[:dir1,dir2,...]]]
```

| Field | Required | Rule | Default |
|---|---|---|---|
| `name` | yes | letters, digits, `.`, `_` and `-`; does not start with `-`; at most 32 characters | |
| `password` | no | any text without `:`, at most 255 characters; empty means no password login | |
| `e` | no | the literal `e`, meaning `password` is a `crypt(3)` hash | plain text, hashed with yescrypt |
| `uid` | no | a number from 1 to 4294967294; may repeat another account's | the next free uid from 1000 |
| `gid` | no | a number from 1 to 4294967294; a missing group is created as `group_<gid>` | 100 (`users`) |
| `dirs` | no | comma-separated relative paths, without `.` or `..` components | none |

Fields are positional, so an empty field keeps its place: `alice:pw:::upload` has no uid or gid and one directory.

## Where lines are read from

In this order; the first definition of a name wins and later ones are warned about:

1. `/etc/sftp-users.conf`, if mounted (the 1.x location)
2. `/config/sshd/users.conf`
3. the file named by `SFTP_USERS_FILE`
4. the container's arguments
5. `SFTP_USERS`, split at spaces

In files, lines that are empty or start with `#` are skipped, and trailing whitespace and carriage returns are removed.

## Examples

```text
# Password login, writable upload directory.
alice:changeme:1001:100:upload

# Public-key login only, two directories, one of them nested.
bob::1002:100:inbox,archive/old

# A yescrypt hash made with mkpasswd.
carol:$y$j9T$6IoIpga7qoVTKEtg7uOmk.$wqs4plcBkLh9AkLUNTXVh2MqiT4GaFcVqfk.9yQ.N/0:e:1003

# Unraid's nobody:users, for shares owned by them.
dave:secret:99:100
```

The hash on `carol`'s line is real `mkpasswd -m yescrypt` output for the password `changeme`.

## What the entrypoint does with each account

- Creates it, or updates the uid, gid and password of an existing one, with shell `/usr/sbin/nologin` and membership in `sftpusers`.
- Creates `/home/<name>` owned by root with mode 755; an existing one is made root-owned and loses group and other write permission, with a warning.
- Creates each missing component of each directory, owned by the account; existing directories are left alone, and nothing is created below a symbolic link.
- Installs keys from `/config/userkeys/<name>.pub` and `/config/userkeys/<name>/*.pub`.
- Deletes accounts it created earlier that are no longer listed, keeping their home directories.
