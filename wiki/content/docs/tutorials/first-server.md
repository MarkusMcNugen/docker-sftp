---
title: Your First Server
weight: 1
---

This tutorial starts a server with two accounts, logs in with a password and with a key, and shares a folder from the host. It takes a machine with Docker and an OpenSSH client (`sftp`), which Linux, macOS and Windows 10 or later include.

## 1. Make the folders

```bash
mkdir -p ~/sftp/config/sshd ~/sftp/config/userkeys ~/sftp/alice
sudo chown 1001:100 ~/sftp/alice
```

`~/sftp/config` becomes the container's `/config`. `~/sftp/alice` will be Alice's upload folder; it belongs to uid 1001 because that is the uid Alice's account will have.

## 2. Describe the accounts

```bash
cat > ~/sftp/config/sshd/users.conf <<'EOF'
alice:changeme:1001:100
bob::1002:100:inbox,outbox
EOF
```

Alice logs in with the password `changeme`. Bob has no password, so he needs a key. Each line's format is in [users.conf](../../reference/users-conf/).

## 3. Give Bob a key

If you have no key yet, make one with `ssh-keygen -t ed25519`. Copy the public half into the config:

```bash
cp ~/.ssh/id_ed25519.pub ~/sftp/config/userkeys/bob.pub
```

## 4. Start the server

```bash
docker run -d --name sftp --restart unless-stopped \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 2222:22 \
  -v ~/sftp/config:/config \
  -v ~/sftp/alice:/home/alice/upload \
  markusmcnugen/sftp
```

`NET_ADMIN` and `NET_RAW` let fail2ban block attackers. Port 2222 on the host reaches the server's port 22.

## 5. Read the start-up log

```bash
docker logs sftp
```

The first lines come from the entrypoint, and each line starts with a timestamp:

```text
entrypoint: generating ed25519 host key in /config/sshd/keys
entrypoint: host key: 256 SHA256:SApi6R5LEGS+C7kXOvZDx+ialFRtBJ2m6/fWYeQjStw sftp-host-key (ED25519)
entrypoint: generating rsa host key in /config/sshd/keys
entrypoint: host key: 4096 SHA256:OFZ+iwhAOgZtZlhbKVPZvz1hRdz5TN/qjPqjWqbvPy8 sftp-host-key (RSA)
entrypoint: user alice: created (uid 1001, gid 100)
entrypoint: user bob: created (uid 1002, gid 100)
entrypoint: user bob: created /home/bob/inbox
entrypoint: user bob: created /home/bob/outbox
entrypoint: user bob: key 256 SHA256:clPGMcqh2mCTz/Rr1jUsIybSZEclxWMUja/uFZqurJM bob@laptop (ED25519)
entrypoint: accounts configured: 2
entrypoint: sshd will listen on port(s): 22
entrypoint: fail2ban bans with iptables (nft backend)
rsyslogd: [origin software="rsyslogd" swVersion="8.2504.0" x-pid="97" x-info="https://www.rsyslog.com"] start
entrypoint: server started
sshd[105]: Server listening on 0.0.0.0 port 22.
sshd[105]: Server listening on :: port 22.
```

fail2ban's start-up lines follow, ending with `Jail 'sshd' started`.

Note the `ED25519` host key fingerprint. Your fingerprints differ, because the keys were just made for this server.

## 6. Log in with a password

```bash
sftp -P 2222 alice@localhost
```

The client asks whether to trust the host key and shows its fingerprint; compare it with the log, then type `yes` and the password. You are in Alice's jail:

```text
Connected to localhost.
sftp> pwd
Remote working directory: /
sftp> ls
upload
sftp> put notes.txt upload/
Uploading notes.txt to /upload/notes.txt
```

`/` is Alice's home, which she cannot write to; `upload` is `~/sftp/alice` on the host, where `notes.txt` now is. Type `exit` to leave.

## 7. Log in with the key

```bash
sftp -P 2222 bob@localhost
```

No password is asked:

```text
sftp> ls
inbox   outbox
```

`inbox` and `outbox` live inside the container; mount host folders there to keep their files when the container is re-created.

## 8. Watch fail2ban

Try `sftp -P 2222 alice@localhost` with a wrong password a few times from another machine, then:

```bash
docker exec sftp fail2ban-client status sshd
```

After five failures within ten minutes, the address appears under `Banned IP list` and its connections are refused for an hour. Lift a ban with `docker exec sftp fail2ban-client set sshd unbanip <address>`.

## Next

- Hash Alice's password instead of storing it in plain text: [How To Use Hashed Passwords](../../how-to/use-hashed-passwords/).
- See every file operation in the log: [How To Log Transfers](../../how-to/log-transfers/).
- Run it with the fewest privileges: [How To Harden The Container](../../how-to/harden-the-container/).
