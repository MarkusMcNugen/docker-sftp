---
title: Log Messages
weight: 6
---

`docker logs` interleaves four sources. Each line starts with a timestamp, left out in the examples below.

| Source | Line looks like |
|---|---|
| entrypoint | `entrypoint: <message>`, `entrypoint: warning: ...`, `entrypoint: fatal: ...` |
| sshd, through rsyslog | `sshd[<pid>]: ...` or `sshd-session[<pid>]: ...` |
| SFTP sessions, with transfer logging | `internal-sftp[<pid>]: ...` |
| fail2ban | `fail2ban.<part> [<pid>]: <LEVEL> ...` |

## Entrypoint

Start-up, with one key user and one password user:

```text
entrypoint: generating ed25519 host key in /config/sshd/keys
entrypoint: host key: 256 SHA256:YnhQbnAD3zmItIVoK+sh7MrrTsm4SFks+e+HqD5An88 sftp-host-key (ED25519)
entrypoint: user alice: created (uid 1001, gid 100)
entrypoint: user alice: created /home/alice/upload
entrypoint: user alice: key 256 SHA256:50dZUXe/YxctLY3ZT95jZWBmLXQ+xENfc55v22plvVg alice@laptop (ED25519)
entrypoint: accounts configured: 2
entrypoint: sshd will listen on port(s): 22
entrypoint: fail2ban bans with iptables (nft backend)
entrypoint: server started
```

A restart after `bob` was removed from `users.conf`:

```text
entrypoint: user bob: removed (no longer configured); /home/bob is kept
```

Shutdown:

```text
entrypoint: received SIGTERM; stopping
sshd[76]: Received signal 15; terminating.
entrypoint: stopped
```

Warnings, each with what it means:

| Warning | Meaning |
|---|---|
| `user bob has no password and no key in /config/userkeys, so cannot log in` | the account exists but nothing lets it in |
| `user bob: no valid public key in /config/userkeys/bob.pub` | the key file holds no key ssh-keygen can read |
| `user "x" is defined more than once; keeping the first definition` | two lines name the same account |
| `user "x": the password is marked :e but does not look like a crypt hash` | the hash does not start with `$` |
| `user x: /home/x was owned by <uid>:<gid>; changed to root:root, which the chroot requires` | an existing home was fixed |
| `fail2ban cannot change firewall rules, so attackers are detected but never blocked. ...` | `NET_ADMIN` or `NET_RAW` is missing |
| `rsyslogd did not create /home/x/dev/log, so transfers in that chroot are not logged. ...` | a host security policy confines rsyslogd |
| `/config/sshd/sshd_config replaces the whole built-in sshd configuration, ...` | an edited 1.x file is in use |
| `/config/fail2ban/fail2ban.conf was written by a 1.x image and is no longer read; ...` | followed by `renamed ... to ....legacy` |
| `user x: manage=y names no account or group, so it grants nothing` | a `manage=` target that does not exist |
| `country rules are not enforced: the firewall refused them (...). Start the container with --cap-add=NET_ADMIN.` | `NET_ADMIN` is missing, or nftables refused the rules for the reason in brackets; the Bans page shows the same |
| `country rules: cannot exempt a never-ban entry: gateway.example ...` | the never-ban list holds a host name, which the firewall cannot match |
| `MaxMind GeoLite2 was not downloaded, so the country rules read the previous copy or DB-IP Lite: ...` | a MaxMind key is set but the download failed, for the reason given |
| `sshd exited with status N; stopping the container` | a service died |

Fatal messages are listed in [How To Fix A Failure](../../how-to/fix-a-failure/).

## sshd

`LogLevel VERBOSE` records the key behind each key login:

```text
sshd-session[125]: Connection from 10.89.0.2 port 46322 on 10.89.0.4 port 22 rdomain ""
sshd-session[125]: Accepted key ED25519 SHA256:50dZUXe/YxctLY3ZT95jZWBmLXQ+xENfc55v22plvVg found at /etc/ssh/authorized_keys/alice:1
sshd-session[125]: Accepted publickey for alice from 10.89.0.2 port 46322 ssh2: ED25519 SHA256:50dZUXe/YxctLY3ZT95jZWBmLXQ+xENfc55v22plvVg
sshd-session[129]: Accepted password for alice from 10.89.0.2 port 46332 ssh2
```

A failed guess, and sshd's own penalty:

```text
sshd-session[137]: Failed password for alice from 10.89.0.3 port 42804 ssh2
sshd-session[137]: Connection closed by authenticating user alice 10.89.0.3 port 42804 [preauth]
sshd[103]: srclimit_penalise: ipv4: new 10.89.0.3/32 deferred penalty of 5 seconds for penalty: failed authentication
```

## fail2ban

```text
fail2ban.filter         [102]: INFO    [sshd] Found 10.89.0.3 - <time of the failure>
fail2ban.actions        [102]: NOTICE  [sshd] Ban 10.89.0.3
fail2ban.actions        [102]: NOTICE  [sshd] Unban 10.89.0.3
```

## Transfers

With `SFTP_LOG_TRANSFERS=true`:

```text
internal-sftp[110]: session opened for local user alice from [10.89.0.3]
internal-sftp[110]: open "/upload/blob" flags WRITE,CREATE,TRUNCATE mode 0644
internal-sftp[110]: close "/upload/blob" bytes read 0 written 4096
internal-sftp[110]: posix-rename old "/upload/blob" new "/upload/blob2"
internal-sftp[110]: remove name "/upload/blob2"
internal-sftp[110]: session closed for local user alice from [10.89.0.3]
```
