---
title: How To Add And Change Users
weight: 1
---

Every account is one line, `name:password[:e][:uid[:gid[:dirs]]]`. The full grammar is in [users.conf](../../reference/users-conf/).

## Add users in a file

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

Lines starting with `#` and blank lines are ignored. Windows line endings and trailing spaces are removed before a line is read, so a file edited over an SMB share works.

Restart the container to apply the file: `docker restart sftp`.

## Add users without a file

The same lines are accepted in three more places, read after `users.conf` in this order:

1. A file named by `SFTP_USERS_FILE`, such as a Docker secret: `-e SFTP_USERS_FILE=/run/secrets/sftp_users`.
2. The container's arguments: `docker run ... markusmcnugen/sftp alice:changeme:1001 bob::1002`.
3. `SFTP_USERS`, space-separated: `-e SFTP_USERS="alice:changeme:1001 bob::1002"`.

When a name appears twice, the first definition wins and the log says so. Passwords in `SFTP_USERS` or the arguments are visible to anyone who can run `docker inspect`; use a hash there.

## Change a user

Edit the line and restart. Every start compares the accounts with the configuration:

| Change | What happens on restart |
|---|---|
| New password | The new password works and the old one stops working |
| New uid or gid | The account is changed; files the user owns under the home directory move with it |
| New directory in `dirs` | It is created and given to the user; existing directories are left alone |
| Key file removed | The key stops working |
| Line removed | The account is deleted; `/home/<name>` and its files are kept |

## What the entrypoint refuses

The container exits before anything listens, with a message naming the account, when a line:

- uses the name of an account that belongs to the image, such as `root` or `sshd`;
- sets uid or gid `0`;
- lists a directory that is absolute or contains `.` or `..`;
- has a uid or gid that is not a number from 1 to 4294967294;
- has more than six fields.

The full list of messages is in [How To Fix A Failure](../fix-a-failure/).
