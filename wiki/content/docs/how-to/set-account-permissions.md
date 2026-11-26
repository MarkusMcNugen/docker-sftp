---
title: How To Set Account Permissions
weight: 3
---

An account's permissions and limits are options at the end of its line in `users.conf`. The web UI writes the same options.

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
1. Open the account from **Accounts**.
2. Under **Permissions**, choose **Full access**, **Read-only** or **Upload-only**, or **Custom** to tick each permission yourself. **From its groups** leaves it to the account's groups ([How To Group Accounts](../group-accounts/)).
3. Under **Access**, set any limits: **Disabled**, **Expires on**, **Allowed networks**, one per line, and **Permissions for new files**, the account's umask.
4. Choose **Save and apply**. The change applies at once, and open sessions stay connected unless the account was disabled or has expired.

![The Permissions section of an account](/screenshots/account-permissions.png)

![The Access section of an account](/screenshots/account-access.png)
{{< /tab >}}
{{< tab name="Command line" >}}
The last field of an account line holds options, separated by commas:

```text
rob:pw:1001:100:pub:readonly
ula:pw:1002:100:drop:uploadonly
cara:pw:1003:100:files:perms=list+download+upload+mkdir
dina:pw:1004:100:up:disabled
exa:pw:1005:100:up:expires=2027-01-31
fio:pw:1006:100:up:from=203.0.113.0/24,from=2001:db8::/32
gus:pw:1007:100:shared:umask=002
```

Apply the change with `docker exec sftp entrypoint apply`, or restart the container ([How To Apply Changes Without A Restart](../apply-changes-live/)).
{{< /tab >}}
{{< /tabs >}}

## Permissions

| Web UI | Option | The account can |
|---|---|---|
| Full access | none, or `full` | everything in its directories |
| Read-only | `readonly` | list and download |
| Upload-only | `uploadonly` | upload, overwrite, rename and make directories, and list names; not download or delete |
| Custom | `perms=a+b+...` | exactly the permissions named |

The permissions are `list`, `download`, `upload`, `delete`, `rename`, `mkdir`, `attributes` (times and modes) and `links`. Without `upload` an account is read-only, so `delete`, `rename`, `mkdir`, `attributes` and `links` need `upload` too. OpenSSH enforces them on every request (`internal-sftp -R` and `-P`).

Upload-only keeps `rename` and `attributes` because clients such as WinSCP upload to a temporary name and set the file's time afterward.

An account with rsync must be full or read-only: rsync does not go through the SFTP requests the other permissions filter. A read-only rsync account may only download, and options that would change files on the server, such as `--remove-source-files`, are refused.

## Disable, expire, limit

| Web UI | Option | Effect |
|---|---|---|
| Disabled | `disabled` | refuses every login but keeps the account, its keys and its files |
| Expires on | `expires=YYYY-MM-DD` | refuses logins from that day on, in UTC |
| Allowed networks | `from=` | allows logins only from those addresses or networks; repeat the option for more |

A network written with host bits, such as `10.0.0.1/8`, is refused. Disabling or expiring an account ends its open sessions when the change is applied.

## umask

**Permissions for new files**, or `umask=002`, gives one account its own umask over `SFTP_UMASK`, for SFTP and rsync alike.
