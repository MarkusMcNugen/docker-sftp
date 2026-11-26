---
title: How To Allow rsync
weight: 8
---

Accounts are SFTP-only unless you allow rsync for them. An allowed account can run `rsync` over SSH, still inside its jail, and nothing else.

## Allow an account

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Open the account from **Accounts**, turn on **rsync over SSH** under **Access**, and choose **Save and apply**. For every member of a group, turn on **Members may use rsync** on the group's page instead.

![The Access section of an account with rsync over SSH on](/screenshots/account-access-rsync.png)
{{< /tab >}}
{{< tab name="Command line" >}}
Either end its line in `users.conf` with the `rsync` option:

```text
alice:changeme:1001:100:upload:rsync
bob::1002:100::rsync
```

or list it in `SFTP_RSYNC_USERS`, separated by spaces, or `*` for every account:

```bash
-e SFTP_RSYNC_USERS="alice bob"
```

Apply a change to `users.conf` with `docker exec sftp entrypoint apply`; a change to the environment needs a restart. The log says `user alice: rsync allowed`.
{{< /tab >}}
{{< /tabs >}}

rsync needs full access or read-only: it does not go through the SFTP requests the other permissions filter ([How To Set Account Permissions](../set-account-permissions/)).

## Use it

```bash
rsync -av -e "ssh -p 2222" ./photos/ alice@server:upload/photos/
rsync -av -e "ssh -p 2222" alice@server:upload/photos/ ./photos/
```

Paths are inside the jail, as in SFTP: `upload/photos/` is `/home/alice/upload/photos` in the container. Key logins work the same way as for SFTP.

## How it works

The account's login shell becomes a gate, `/usr/local/libexec/sftp/rsync-gate`, which runs a command only if it is an rsync server command (`rsync --server ...`) and refuses every other one with `This service allows sftp and rsync connections only.` Each time the configuration is applied, the entrypoint copies `sh`, `rsync`, the gate and the libraries they load into the account's home, root-owned, at the paths they have in the image; the jail is unchanged, so `/` in the session is still the home directory. The user sees root-owned `bin`, `lib`, `lib64` and `usr` folders there and cannot change them.

The account's SFTP sessions keep transfer logging and `SFTP_UMASK`.

## Take it away

Turn **rsync over SSH** off, or remove the `rsync` option or the name, and apply: the copied files are removed and the account is SFTP-only again.

## When it is refused

- An account whose home already holds a `bin`, `lib`, `lib64` or `usr` folder of its own is not given rsync, and the log says `/home/alice/usr belongs to the user, so rsync is not set up in this jail`. Rename that folder.
- `SFTP_RSYNC_USERS names "x", which is not a configured account` stops the container.
- A client that sees `protocol incompatibility` is talking to an account without rsync.
