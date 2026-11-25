---
title: Security Model
weight: 2
---

## What a user can do

A user can only transfer files. sshd's `ForceCommand internal-sftp` runs the SFTP server for every session, so a command, a shell or a terminal is refused, and all forwarding is disabled: ports, agents, Unix sockets, X11 and tunnels. Accounts have the `nologin` shell as a second barrier.

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

The container needs ten Linux capabilities and runs with `no-new-privileges`; [How To Harden The Container](../../how-to/harden-the-container/) lists them. fail2ban needs `NET_ADMIN` and `NET_RAW`; without them it still detects attacks but cannot block them, and the log says so.

## Host security policies

On an Ubuntu host, a container started without an AppArmor profile of its own, as rootless Podman does, has the host's profile for `/usr/sbin/rsyslogd` applied to the container's rsyslogd. That profile forbids the log sockets inside jails, so transfers go unlogged and the entrypoint warns. Everything else, including fail2ban's auth log, works.

## What runs as root

The entrypoint and startup scripts run as root, and anyone who can write `/config` can change accounts and run scripts. Protect the `/config` volume like a password file.
