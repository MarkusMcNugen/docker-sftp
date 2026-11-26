---
title: How To Add And Change Users
weight: 1
---

Each account is one line of `/config/sshd/users.conf`. The admin web UI edits that same file, so either way gives the same result. The full grammar is in [users.conf](../../reference/users-conf/).

## Add an account

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
1. Open **Accounts** and choose **New account**.
2. Enter the name. Leave **User ID** and **Group ID** empty to take the next free user ID and group 100, `users`.
3. Under **Writable directories**, list the folders the account may write to, one per line, such as `upload`.
4. Under **Password**, set one, or choose **No password** for an account that logs in with a public key only.
5. Under **Permissions**, choose what it may do ([How To Set Account Permissions](../set-account-permissions/)), then **Create account**.

The account can log in at once. Nothing restarts, and open sessions stay connected.

![The form for a new account](/screenshots/account-new.png)
{{< /tab >}}
{{< tab name="Command line" >}}
Put one line per account in `/config/sshd/users.conf`:

```text
# /config/sshd/users.conf
alice:changeme:1001:100:upload
bob::1002:100:inbox,outbox
carol:$y$j9T$Y3oP...:e:1003
```

- `alice` logs in with a password and can write to `/upload` inside her jail.
- `bob` has no password, so he logs in only with a public key ([How To Use Public Keys](../use-public-keys/)).
- `carol`'s password is a hash ([How To Use Hashed Passwords](../use-hashed-passwords/)).

Lines starting with `#` and blank lines are skipped. Windows line endings and trailing spaces are removed before a line is read, so a file edited over an SMB share works.

Apply the file to the running server; open sessions stay connected:

```bash
docker exec sftp entrypoint apply
```
{{< /tab >}}
{{< /tabs >}}

The **Accounts** page lists every account, how it logs in, its directories and IDs, and where it is defined.

![The Accounts page](/screenshots/accounts.png)

## Add accounts without a file

The same lines are accepted in three more places, read after `users.conf` in this order:

1. A file named by `SFTP_USERS_FILE`, such as a Docker secret: `-e SFTP_USERS_FILE=/run/secrets/sftp_users`.
2. The container's arguments: `docker run ... markusmcnugen/sftp alice:changeme:1001 bob::1002`.
3. `SFTP_USERS`, separated by spaces: `-e SFTP_USERS="alice:changeme:1001 bob::1002"`.

When a name appears twice, the first definition wins and the log says so. Passwords in `SFTP_USERS` or the arguments are visible to anyone who can run `docker inspect`; use a hash there. The web UI lists these accounts and names where each is defined, and changes them only in `users.conf`.

## Change an account

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Open the account from **Accounts**, change what you need, and choose **Save and apply**.
{{< /tab >}}
{{< tab name="Command line" >}}
Edit the account's line in `users.conf`, then run `docker exec sftp entrypoint apply`, or restart the container.
{{< /tab >}}
{{< /tabs >}}

| Change | What happens when it is applied |
|---|---|
| New password | The new password works and the old one stops working |
| New uid or gid | The account is changed; files the user owns under the home directory move with it |
| New writable directory | It is created and given to the user; existing directories are left alone |
| Key removed | The key stops working |
| Account disabled, expired or removed | Its open sessions end |
| Account removed | `/home/<name>` and its files are kept |

## What the entrypoint refuses

A line is refused, with a message naming the account, when it:

- uses the name of an account that belongs to the image, such as `root` or `sshd`;
- sets uid or gid `0`, or `980` or `981`, which belong to the web UI and the file browser;
- has a uid or gid that is not a number from 1 to 4294967294;
- lists a directory that is absolute or contains `.` or `..`;
- names an option that does not exist, or the same option twice.

At start, a refused line stops the container before anything listens. `entrypoint apply` and the web UI refuse the change and keep the running configuration. The full list of messages is in [How To Fix A Failure](../fix-a-failure/).
