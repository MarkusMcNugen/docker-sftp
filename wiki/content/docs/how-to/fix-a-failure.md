---
title: How To Fix A Failure
weight: 12
---

Each entry starts with the text you see, in `docker logs` or in your SFTP client.

## The container stops at start

**`fatal: no users configured. Add them to /config/sshd/users.conf, SFTP_USERS or the command line.`** (exit status 3)
No account was found anywhere. The container has written a commented template to `/config/sshd/users.conf`; add a line and start it again.

**`fatal: user "root" is a system account of the image; choose another name`**
The name belongs to an account the image itself uses, such as `root`, `sshd` or `nobody`. Pick another name.

**`fatal: user "eve": directory "../etc" may not contain . or ..`**, **`must be relative to the home directory`**
Directories in the last field are created inside the user's home. Write `upload` or `data/inbox`, not `/upload` or `../etc`.

**`fatal: user "eve": uid "abc" must be a number from 1 to 4294967294 (0 is root)`**
The uid and gid fields take numbers. uid and gid 0 are refused because they are root's.

**`fatal: SFTP_PORT=70000 is not a port number`**, **`fatal: SFTP_CRYPTO_POLICY=weak must be modern or strict`**, **`fatal: SFTP_AUTH_LOG_MAX_BYTES=10MB is not a byte count (0 means no cap)`**, **`fatal: FAIL2BAN_ENABLED=maybe must be true or false`**
An environment variable has a value the image does not accept. [Environment Variables](../../reference/environment-variables/) lists the accepted values.

**`fatal: sshd rejected its configuration: ...`**
A file in `/config/sshd/sshd_config.d/`, or `/config/sshd/sshd_config`, has a mistake. The rest of the line is sshd's own message, naming the file and line.

**`fatal: fail2ban rejected its configuration: ...`**
A file in `/config/fail2ban/` has a mistake. The rest of the line is fail2ban's message.

**`fatal: /config/sshd/scripts/<file> failed with status N`**
A startup script exited with an error. Run it by hand with `docker exec` to see why, or remove it.

## The container stops while running

**`warning: sshd exited with status N; stopping the container`** (or `fail2ban`, `rsyslog`)
One of the services died, so the whole container stopped and the restart policy starts it again. The lines above this one say why the service died.

## A user cannot log in

**Client: `Permission denied (publickey,password)`**
- Wrong password, or a key that is not in `/config/userkeys`. The log line from sshd says which: `Failed password for alice`, or no `Accepted key` line.
- An account with no password and no key: the log says `user bob has no password and no key in /config/userkeys, so cannot log in`.
- A key file with no valid key in it: `user bob: no valid public key in /config/userkeys/bob.pub`.

**Client: `Connection refused` or a timeout, from one address only**
That address is banned. `docker exec sftp fail2ban-client status sshd` lists bans; `fail2ban-client set sshd unbanip <address>` lifts one.

**Client: `Unable to negotiate ... no matching MAC found` (or cipher, or key exchange method)**
The client offers only algorithms the server refuses. Update the client, or, for a missing MAC with `SFTP_CRYPTO_POLICY=strict`, return to the `modern` policy.

**Client: `This service allows sftp connections only.`**
`ssh` was used instead of `sftp`. The server accepts only file transfer.

## A user cannot write

**`Permission denied` on upload**
- The user is writing to `/`, their home, which belongs to root. They must write into a subdirectory.
- A mounted host directory belongs to another uid. The container does not change the owner of an existing directory; run `chown <uid>:<gid>` on the host. [How To Share Host Directories](../share-host-directories/).

## Bans do not happen

**`warning: fail2ban cannot change firewall rules, so attackers are detected but never blocked.`**
Start the container with `--cap-add NET_ADMIN --cap-add NET_RAW`.

**Every client is banned at once**
All connections reach the container from one address, such as a proxy's. See [Security Model](../../explanation/security-model/#client-addresses).

## Transfers are not logged

**`warning: rsyslogd did not create /home/alice/dev/log, so transfers in that chroot are not logged.`**
A security policy on the host confines rsyslogd. [How To Log Transfers](../log-transfers/#when-transfers-are-not-logged).

## Upgrading

**`warning: /config/sshd/sshd_config replaces the whole built-in sshd configuration, so its hardening and sshd_config.d drop-ins do not apply`**
An edited 1.x `sshd_config` is still in `/config`. [How To Upgrade From 1.x](../upgrade-from-1x/).
