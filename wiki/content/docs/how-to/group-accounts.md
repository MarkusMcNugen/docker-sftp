---
title: How To Group Accounts
weight: 15
---

A group gives its members defaults: permissions, rsync, file browser access, limits and the accounts they may manage. Groups live in `/config/sshd/groups.conf`, and the admin web UI's **Groups** page edits them.

## Define a group

One group per line:

```text
name[:gid[:options]]
```

```text
readers:2300:readonly,umask=077
partners:2301:uploadonly,from=203.0.113.0/24
staff::web,manage=@partners
contractors::expires=2027-03-31,noshare
```

The gid, when given, is the Unix group of members' files unless an account sets its own. The options are those of an account line, except `group=`; [users.conf](../../reference/users-conf/) lists them.

## Put an account in a group

```text
ann:pw:1001::up:group=staff
ben:pw:1002::drop:readonly,group=partners,group=readers
```

`group=` repeats, and the first of an account's groups with a gid gives the account its primary group. In the web UI, add members on the group's page or groups on the account's page; saving writes `group=` on each account's line.

## How defaults combine

An account takes from its groups what its own line leaves unset:

| Kind | Options | Across groups |
|---|---|---|
| Grants | permissions, `rsync`, `web`, `from=`, `manage=` | add up: what any group gives, the account has |
| Limits | `disabled`, `expires=`, `umask=` | the strictest: disabled if any group is, the earliest date, every umask bit any group sets |
| Share link limits | `noshare`, `sharedays=`, `sharepassword` | the strictest, and the account's own line cannot loosen them |

Permissions, networks, an end date, a umask or a gid on the account's own line win over its groups. An account that names no permissions and whose groups give none has full access.

## Let one account manage others

`manage=name` lets an account open another account's files in the [file browser](../use-the-file-browser/), and `manage=@group` every member of a group, now and later. Each account's own permissions apply, and what the manager does is logged under both names. On a group's line, `manage=` lets every member manage those accounts.

Managing needs the file browser: the manager needs `web`, and the managed accounts need nothing.
