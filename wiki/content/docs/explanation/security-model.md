---
title: Security Model
weight: 2
---

## What a user can do

A user can only transfer files. sshd's `ForceCommand internal-sftp` runs the SFTP server for every session, so a command, a shell or a terminal is refused, and all forwarding is disabled: ports, agents, Unix sockets, X11 and tunnels. Accounts have the `nologin` shell as a second barrier.

Accounts allowed rsync are the one exception: their login shell is a gate that runs an rsync server command and refuses everything else. To make that possible, their jail holds root-owned copies of `sh`, `rsync` and the libraries they load, which the user can run only through the gate and cannot change ([How To Allow rsync](../../how-to/allow-rsync/)).

Each session runs inside the user's home with `ChrootDirectory %h`: `/` in the session is `/home/<name>`. Because the jail's root must belong to root, a user writes only into subdirectories given to them.

## Keys outside the jail

Authorized keys are read from `/etc/ssh/authorized_keys/<name>`, owned by root and outside every jail. With keys inside the home, as `~/.ssh/authorized_keys`, any user able to write there could add a key and hand out access.

## Who may log in

`AllowGroups sftpusers` admits only the accounts the entrypoint created. `PermitRootLogin no` refuses root even with a key. Passwords are hashed with yescrypt when given in plain text.

## Cryptography

A connection agrees on a key exchange, which sets up the session keys; a cipher, which encrypts the data; and a MAC (message authentication code), which detects tampering. Encrypt-then-MAC computes the MAC over the encrypted data, the stronger of the two orders. AEAD ciphers such as AES-GCM and ChaCha20-Poly1305 authenticate the data themselves and need no separate MAC. A post-quantum hybrid key exchange combines a classical exchange with ML-KEM, which is designed to withstand quantum computers, so a recording of today's session cannot be decrypted by one later.

| Kind | Allowed |
|---|---|
| Key exchange | `mlkem768x25519-sha256` (post-quantum hybrid) first, then `sntrup761x25519`, `curve25519`, and Diffie-Hellman groups 16, 18 and group exchange with moduli of at least 3072 bits |
| Ciphers | ChaCha20-Poly1305, AES-GCM, AES-CTR |
| MACs | encrypt-then-MAC SHA-2 and UMAC-128; plain `hmac-sha2-256` and `hmac-sha2-512` last, unless `SFTP_CRYPTO_POLICY=strict` |
| Keys | Ed25519, ECDSA, security keys, RSA of at least 2048 bits with SHA-2 signatures |

SHA-1 anywhere, CBC ciphers, MD5 and 64-bit MACs are refused. The full lists are in [Built-in Settings](../../reference/built-in-settings/).

## Brute force

Three mechanisms slow down guessing:

- `MaxAuthTries 4` ends a connection after four failed attempts, and `LoginGraceTime 30` after thirty seconds without logging in.
- sshd's per-source penalties delay, then refuse, an address after repeated failures.
- fail2ban bans an address for an hour after five failures within ten minutes, doubling for each repeat up to a week. Bans survive restarts.

## Client addresses

Both sshd's penalties and fail2ban act on the address the connection comes from. Docker's port publishing keeps the client's real address. Anything that proxies the connection replaces it with its own: a reverse proxy, a load balancer, or Docker's userland proxy (which handles some connections, such as from the host itself). Then every client shares one address, and one attacker gets everyone banned. In those setups use host networking, or put the protection on the proxy.

## Capabilities

The container needs ten Linux capabilities and runs with `no-new-privileges`; [How To Harden The Container](../../how-to/harden-the-container/) lists them. fail2ban needs `NET_ADMIN` and `NET_RAW`; without them it still detects attacks but cannot block them, and the log says so. The country rules need `NET_ADMIN` too; without it the firewall refuses them and the Bans page says they are not enforced.

## Host security policies

On an Ubuntu host, a container started without an AppArmor profile of its own, as rootless Podman does, has the host's profile for `/usr/sbin/rsyslogd` applied to the container's rsyslogd. That profile forbids the log sockets inside jails, so transfers go unlogged and the entrypoint warns. Everything else, including fail2ban's auth log, works.

## The admin web UI

The web UI is off unless `WEBUI_ENABLED` is true. When on, it is split in two:

- `sftp-webui`, the web server, runs as the system user `sftp-webui` (uid 980) with an empty environment, no capabilities and `no-new-privileges`. It holds the admins and their sessions.
- `sftp-helper` runs as root and listens on a Unix socket that only the `sftp-webui` user may use, which it checks on every connection. It carries out a fixed list of typed requests, validates every field with the same rules as the entrypoint, and applies every change to files with `entrypoint apply`; if apply refuses, it puts every file back. Bans and ended sessions go to fail2ban and the session's process directly.

So a flaw in the web server gives an attacker what a full admin has, which is managing SFTP accounts, and not root: the helper writes users.conf, groups.conf, settings.conf, public keys, the fail2ban rules and the file browser's sign-ins and share links, never startup scripts or sshd configuration, and refuses uid and gid 0, 980 and 981. Keys are accepted only without options, so none can carry `command=`.

Sign-in uses a password hashed with argon2id (64 MiB, three passes) and, optionally, a time-based code that is accepted once. The session cookie is `Secure`, `HttpOnly` and `SameSite=Strict`, its id is rotated at sign-in, and sessions end after 30 idle minutes or 12 hours. Every change needs the session's CSRF token, and the browser's `Sec-Fetch-Site` must say the request came from the UI's own pages. Pages carry a Content-Security-Policy that allows only the UI's own scripts and styles, and nothing is loaded from elsewhere. TLS is version 1.3 only.

Every change is recorded with the admin and address in `/config/audit/webui.log`, which only root can write, and in the container log.

## The file browser

The file browser is off unless `WEBUI_FILES_ENABLED` is true, and lets in only accounts with the `web` option. It runs as its own system user, `sftp-files` (uid 981), with no capabilities and `no-new-privileges`, and it never holds a stored password or second factor: the helper checks each sign-in, and the same throttle, lockout and fail2ban jail apply as for admins.

It reads and writes files only through SFTP, to a second sshd that listens on loopback alone. That sshd accepts nothing but certificates signed by the file browser's certificate authority, whose key only root can read, and only for accounts with web access and the accounts they manage. The helper signs a certificate for a key the file browser makes, for one account, valid for five minutes. The public sshd does not trust that authority. So in the file browser each account keeps its own permissions and jail, and every operation is logged as an SFTP operation.

Every request is checked again with the helper: an account that loses web access, is disabled, passes its end date, or connects from outside its `from=` networks or the country rules is signed out at its next request.

Previews are served with a Content-Security-Policy that sandboxes them and forbids scripts. A PDF opens in the browser's own viewer only when its content starts as a PDF, and an SVG is served only as an image. Archive entries whose path would leave the folder are refused.

## Share links

A share link's token is 32 random bytes, carried after the `#` of the address, so it is in no address a server or a proxy logs. The server keeps only its SHA-256. A link works for one completed download; a download that fails gives it back. It ends after the length its maker chose, within the policy, and a password, when it has one, is kept as an argon2id hash.

Every failure to open a link reads the same, whether the link was used, expired or never existed, so guessing learns nothing; wrong passwords count toward the address's lockout and fail2ban. The file is read with a certificate for its account, so that account's permissions decide whether it can be read at all.

## Country rules

The country rules are enforced twice: by an nftables table in the container's network namespace, before a connection reaches sshd or the web servers, and by the web servers on every request. Loopback, private ranges, `WEBUI_TRUSTED_NETWORKS` and the never-ban list always pass, so a wrong list cannot lock out the local network. A reload builds the new lists beside the old ones and switches in one transaction, so there is no moment without the rules.

## What runs as root

The entrypoint and startup scripts run as root, and anyone who can write `/config` can change accounts and run scripts. Protect the `/config` volume like a password file.
