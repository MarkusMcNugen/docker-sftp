---
title: How To Set Account Permissions
weight: 3
---

The last field of an account line holds options, separated by commas. The web UI writes the same options.

```text
rob:pw:1001:100:pub:readonly
ula:pw:1002:100:drop:uploadonly
cara:pw:1003:100:files:perms=list+download+upload+mkdir
dina:pw:1004:100:up:disabled
exa:pw:1005:100:up:expires=2027-01-31
fio:pw:1006:100:up:from=203.0.113.0/24,from=2001:db8::/32
gus:pw:1007:100:shared:umask=002
```

## Permissions

| Option | The account can |
|---|---|
| none | everything in its directories |
| `readonly` | list and download |
| `uploadonly` | upload, overwrite, rename and make directories, and list names; not download or delete |
| `perms=a+b+...` | exactly the permissions named |

The permissions are `list`, `download`, `upload`, `delete`, `rename`, `mkdir`, `attributes` (times and modes) and `links`. Without `upload` an account is read-only, so `delete`, `rename`, `mkdir`, `attributes` and `links` need `upload` too. OpenSSH enforces them on every request (`internal-sftp -R` and `-P`).

`uploadonly` keeps `rename` and `attributes` because clients such as WinSCP upload to a temporary name and set the file's time afterward.

An account with `rsync` must be full or read-only: rsync does not go through the SFTP requests the other permissions filter. A read-only rsync account may only download, and options that would change files on the server, such as `--remove-source-files`, are refused.

## Disable, expire, limit

- `disabled` refuses every login but keeps the account, its keys and its files.
- `expires=YYYY-MM-DD` refuses logins from that day on, in UTC.
- `from=` limits logins to an address or network; repeat it for more. A network written with host bits, such as `10.0.0.1/8`, is refused.

Disabling or expiring an account ends its open sessions when the change is applied.

## umask

`umask=002` gives one account its own umask, over `SFTP_UMASK`, for SFTP and rsync alike.

## Apply the change

Restart the container, or apply without a restart ([How To Apply Changes Without A Restart](../apply-changes-live/)).
