---
title: How To Group Accounts
weight: 15
---

A group gives its members defaults: permissions, rsync, file browser access, limits and the accounts they may manage. Groups are lines of `/config/sshd/groups.conf`, and the admin web UI's **Groups** page edits that file.

![The Groups page](/screenshots/groups.png)

## Define a group

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
1. Open **Groups** and choose **New group**.
2. Enter its name. **Files' group** is the Unix group ID of members' files, unless an account sets its own; leave it empty for none.
3. Under **Defaults for members**, choose the permissions and limits members get, and whether they may use rsync or the file browser.
4. Save. The defaults apply to every member at once.

![A group's page, with its members and their defaults](/screenshots/group-partners.png)
{{< /tab >}}
{{< tab name="Command line" >}}
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

The gid, when given, is the Unix group of members' files unless an account sets its own. The options are those of an account line, except `group=`; [users.conf](../../reference/users-conf/) lists them. Apply the change with `docker exec sftp entrypoint apply`.
{{< /tab >}}
{{< /tabs >}}

## Put an account in a group

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Add the account under **Members** on the group's page, or add the group under **Groups** on the account's page. Either way, saving writes `group=` on the account's line.
{{< /tab >}}
{{< tab name="Command line" >}}
```text
ann:pw:1001::up:group=staff
ben:pw:1002::drop:readonly,group=partners,group=readers
```

`group=` repeats, and the first of an account's groups with a gid gives the account its primary group.
{{< /tab >}}
{{< /tabs >}}

## How defaults combine

An account takes from its groups what its own line leaves unset:

| Kind | Options | Across groups |
|---|---|---|
| Grants | permissions, `rsync`, `web`, `from=`, `manage=` | add up: what any group gives, the account has |
| Limits | `disabled`, `expires=`, `umask=` | the strictest: disabled if any group is, the earliest date, every umask bit any group sets |
| Share link limits | `noshare`, `sharedays=`, `sharepassword` | the strictest, and the account's own line cannot loosen them |

Permissions, networks, an end date, a umask or a gid on the account's own line win over its groups. An account that names no permissions and whose groups give none has full access.

## Let one account manage others

`manage=name` lets an account open another account's files in the [file browser](../use-the-file-browser/), and `manage=@group` every member of a group, now and later. In the web UI this is **Can open the files of** on the account's page, or **Members can open the files of** on a group's page. Each account's own permissions apply, and what the manager does is logged under both names. On a group, it lets every member manage those accounts.

Managing needs the file browser: the manager needs `web`, and the managed accounts need nothing.
