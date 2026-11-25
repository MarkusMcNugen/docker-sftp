---
title: How To Harden The Container
weight: 8
---

The integration suite runs the image with every capability dropped except the ten below and with `no-new-privileges`, and checks that logins and uploads work.

```yaml
services:
  sftp:
    image: markusmcnugen/sftp:2
    restart: unless-stopped
    ports:
      - "2222:22"
    volumes:
      - ./config:/config
      - ./data/alice:/home/alice/upload
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - FOWNER
      - SETUID
      - SETGID
      - SYS_CHROOT
      - KILL
      - NET_BIND_SERVICE
      - NET_ADMIN
      - NET_RAW
    security_opt:
      - no-new-privileges:true
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
```

| Capability | Needed by |
|---|---|
| `CHOWN`, `DAC_OVERRIDE`, `FOWNER` | the entrypoint, to own and set modes on homes, directories and keys |
| `SETUID`, `SETGID` | sshd, to switch to the user after login |
| `SYS_CHROOT` | sshd, to jail the session |
| `KILL` | sshd and the entrypoint, to stop processes owned by other users |
| `NET_BIND_SERVICE` | sshd, to listen on port 22 |
| `NET_ADMIN`, `NET_RAW` | fail2ban, to add and remove firewall rules |

## More measures

- Use public keys and no passwords: leave the password field empty ([How To Use Public Keys](../use-public-keys/)).
- Set `SFTP_CRYPTO_POLICY=strict` if every client supports encrypt-then-MAC or an AEAD cipher, one that authenticates the data itself such as AES-GCM ([Security Model](../../explanation/security-model/#cryptography)).
- Keep host keys: they are in `/config/sshd/keys`. A new key each time makes clients warn about a changed host, which trains users to ignore the warning.
- Rotate the container log on the Docker side, as above. Docker's default `json-file` driver keeps everything.
- Pin a major version tag such as `:2` rather than `:latest`. The weekly rebuild updates every tag of the newest release.

The image itself cannot run with a read-only root filesystem, because every start rewrites the account database and the sshd and fail2ban configuration.
