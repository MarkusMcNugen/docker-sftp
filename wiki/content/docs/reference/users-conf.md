---
title: users.conf
weight: 2
---

## Grammar

```text
name:password[:e][:uid[:gid[:dir1,dir2,...[:options]]]]
```

| Field | Required | Rule | Default |
|---|---|---|---|
| `name` | yes | letters, digits, `.`, `_` and `-`; does not start with `-`; at most 32 characters | |
| `password` | no | any text without `:`, at most 255 characters; empty means no password login | |
| `e` | no | the literal `e`, meaning `password` is a `crypt(3)` hash | plain text, hashed with yescrypt |
| `uid` | no | a number from 1 to 4294967294 except 980 and 981, the web UI's and the file browser's; may repeat another account's | the next free uid from 1000 |
| `gid` | no | a number from 1 to 4294967294 except 980 and 981; a missing group is created as `group_<gid>` | 100 (`users`), or the first of its groups with a gid |
| `dirs` | no | comma-separated relative paths, without `.` or `..` components or control characters | none |
| `options` | no | the rest of the line, comma-separated, from the table below | full access, SFTP only |

| Option | Effect |
|---|---|
| `rsync` | allows rsync over SSH ([How To Allow rsync](../../how-to/allow-rsync/)) |
| `web` | lets the account sign in to the file browser, with a web password and two-factor set through a sign-in link an admin makes |
| `full`, `readonly`, `uploadonly`, `perms=a+b+...` | permissions ([How To Set Account Permissions](../../how-to/set-account-permissions/)); one of the four, and `full` is needed only over groups that give less |
| `disabled` | refuses every login |
| `expires=YYYY-MM-DD` | refuses logins from that day on, in UTC |
| `from=address-or-network` | allows logins only from there; repeatable |
| `umask=NNN` | the account's own umask |
| `noshare` | no share links to the account's files, and none made by it |
| `sharedays=N` | share links last at most N days, from 1 to 999999999 |
| `sharepassword` | share links to the account's files, and those it makes, need a password |
| `group=name` | takes what the line leaves unset from that group in `/config/sshd/groups.conf`; repeatable, and the first group with a gid gives the primary group |
| `manage=name`, `manage=@group` | may open that account's files, or those of every member of the group, in the file browser, with each account's own permissions; repeatable |

A group's options are an account line's, without `group=`. Grants add up across an account's groups, limits take the strictest, and what the account's own line sets wins, except the share link limits: every `noshare`, `sharepassword` and the shortest `sharedays=` from the line, its groups and the Settings page apply.

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
