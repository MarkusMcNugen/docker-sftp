---
title: Your First Server
weight: 1
---

This tutorial starts a server, adds two accounts, logs in with a password and with a key, shares a folder from the host, opens it in the file browser, and watches fail2ban ban an address. Each step that changes the server shows the admin web UI and the command line side by side; follow either. It takes a machine with Docker, an OpenSSH client (`sftp`), which Linux, macOS and Windows 10 or later include, and a browser.

## 1. Make the folders

```bash
mkdir -p ~/sftp/config/sshd ~/sftp/config/userkeys ~/sftp/alice
sudo chown 1001:100 ~/sftp/alice
```

`~/sftp/config` becomes the container's `/config`. `~/sftp/alice` will be Alice's upload folder; it belongs to uid 1001 because that is the uid Alice's account will have.

## 2. Describe the accounts

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Nothing to write yet: you make both accounts in the browser once the server runs, in step 5. With the web UI on, a server with no account starts and waits for its first admin.
{{< /tab >}}
{{< tab name="Command line" >}}
Describe them in `users.conf`, and give Bob your public key. If you have no key yet, make one with `ssh-keygen -t ed25519`.

```bash
cat > ~/sftp/config/sshd/users.conf <<'EOF'
alice:changeme:1001:100::web
bob::1002:100:inbox,outbox
EOF
cp ~/.ssh/id_ed25519.pub ~/sftp/config/userkeys/bob.pub
```

Alice logs in with the password `changeme`, and `web` lets her use the file browser. Bob has no password, so he needs the key. Each line's format is in [users.conf](../../reference/users-conf/).
{{< /tab >}}
{{< /tabs >}}

## 3. Start the server

```bash
docker run -d --name sftp --restart unless-stopped \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -p 2222:22 -p 8443:8443 -p 8444:8444 \
  -e WEBUI_ENABLED=true -e WEBUI_FILES_ENABLED=true \
  -v ~/sftp/config:/config \
  -v ~/sftp/alice:/home/alice/upload \
  markusmcnugen/sftp
```

`NET_ADMIN` and `NET_RAW` let fail2ban block attackers. Port 2222 on the host reaches the server's port 22, 8443 is the admin web UI and 8444 the file browser. Both are optional: without the two `-e` options and their ports, the server runs from `/config` alone, and then it needs an account in `users.conf` before it starts.

## 4. Read the start-up log

```bash
docker logs sftp
```

These are the entrypoint's and the web UI's lines, each after a timestamp; sshd, fail2ban and rsyslog add their own start-up lines between them.

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
```text
entrypoint: warning: no account yet, so every SFTP sign-in fails; add one on the web UI's Accounts page
entrypoint: generating ed25519 host key in /config/sshd/keys
entrypoint: host key: 256 SHA256:pkapETEQT/VvGQW7iF80mh7UbiL23bBzPWKopZ3hQOc sftp-host-key (ED25519)
entrypoint: generating rsa host key in /config/sshd/keys
entrypoint: host key: 4096 SHA256:GqX6BpjgFeO1c9S7I0Py4gApLQ8dl1nOuld0LCkew4c sftp-host-key (RSA)
entrypoint: generating the file browser's certificate authority in /config/sshd/keys
entrypoint: accounts configured: 0
entrypoint: sshd will listen on port(s): 22
entrypoint: file browser sshd: loopback port 2299, for no account yet
entrypoint: fail2ban bans with iptables (nft backend)
entrypoint: file browser started on port 8444
entrypoint: web UI started on port 8443
entrypoint: server started
sftp-webui: generated a self-signed certificate in /config/webui/tls
sftp-webui: TLS certificate SHA-256 fingerprint 2B:C3:63:16:19:1A:71:48:5B:24:DC:7E:E2:59:3E:54:4A:3B:89:85:BA:B5:F7:77:81:72:F7:41:57:E5:91:4F
sftp-webui: no admin exists yet; within one hour, open https://<this server>:8443/setup?token=7WQ2tR6WZwlqCOCDuB9XFtTH2mF_oY5w3XjTRxd4IOc to create one
```
{{< /tab >}}
{{< tab name="Command line" >}}
```text
entrypoint: generating ed25519 host key in /config/sshd/keys
entrypoint: host key: 256 SHA256:mZhro+dmvOr0+7w8HVZ7HZLfay5NCcCtzNTYz3MJWRU sftp-host-key (ED25519)
entrypoint: generating rsa host key in /config/sshd/keys
entrypoint: host key: 4096 SHA256:KZMzqEoKOQjbxdQScoqBpPrDeNwZ638MzPlZEP5nKJg sftp-host-key (RSA)
entrypoint: generating the file browser's certificate authority in /config/sshd/keys
entrypoint: user alice: created (uid 1001, gid 100)
entrypoint: user bob: created (uid 1002, gid 100)
entrypoint: user bob: created /home/bob/inbox
entrypoint: user bob: created /home/bob/outbox
entrypoint: user bob: key 256 SHA256:6nD8EqFX6lw8f14ydWJtnRVHiPdWcFIVMqSRhvH/q8Y bob@laptop (ED25519)
entrypoint: accounts configured: 2
entrypoint: sshd will listen on port(s): 22
entrypoint: file browser sshd: loopback port 2299, for alice
entrypoint: fail2ban bans with iptables (nft backend)
entrypoint: file browser started on port 8444
entrypoint: web UI started on port 8443
entrypoint: server started
sftp-webui: no admin exists yet; within one hour, open https://<this server>:8443/setup?token=qrKUemxFtzdUq7EyyM4k0As2fOE_Skf66Skf2fMv5YQ to create one
```
{{< /tab >}}
{{< /tabs >}}

Note the `ED25519` host key fingerprint, which your SFTP client shows you in step 6, and the setup link, which works once, for one hour. Your fingerprints and link differ, because they were just made for this server.

## 5. Sign in and make the accounts

Find the setup link in the log, open it with `<this server>` replaced by the machine's address, and choose a name and a password for the first admin. Your browser warns once about the self-signed certificate; the log prints its fingerprint to compare.

```bash
docker logs sftp 2>&1 | grep setup
```

![Creating the first admin from the setup link](/screenshots/setup.png)

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Open **Accounts** and choose **New account**:

- **Name** `alice`, **Set a new password** `changeme`, **User ID** `1001`, **Full access**, and **File browser** on. Choose **Create account**.
- **Name** `bob`, **No password**, **User ID** `1002`, and `inbox` and `outbox` under **Writable directories**, one per line. Choose **Create account**, then paste your public key into **Add keys** on Bob's **Public keys** card. If you have no key yet, make one with `ssh-keygen -t ed25519` and paste `~/.ssh/id_ed25519.pub`.

![The New account page](/screenshots/account-new.png)

![The Public keys card of an account](/screenshots/account-keys.png)
{{< /tab >}}
{{< tab name="Command line" >}}
`users.conf` made both accounts when the server started; **Accounts** lists them. To change them later, edit the file and run `docker exec sftp entrypoint apply`, which changes the server without a restart.
{{< /tab >}}
{{< /tabs >}}

The **Status** page shows who is connected and the sign-ins and transfers of the last day.

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

## 8. Open Alice's files in the browser

The file browser lets an account holder work with their files in a browser, through SFTP with the account's own permissions. On Alice's page in the web UI, choose **Make a sign-in link** in the **File browser** card; the link works once. Opened by Alice, it sets her web password, of at least 12 characters, and a second factor in an authenticator app. She then signs in at `https://<this server>:8444/` and finds `notes.txt` in `upload`.

![Setting up a file browser sign-in from the link](/screenshots/files-invite-alice.png)

![The file browser](/screenshots/files-details.png)

## 9. Watch fail2ban

Try `sftp -P 2222 alice@localhost` with a wrong password a few times from another machine. After five failures within ten minutes, the address is banned and its connections are refused for an hour.

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
The **Bans** page lists the address, where it was banned from and how long the ban lasts. Lift it with the button at the end of its row.

![The Bans page](/screenshots/bans.png)
{{< /tab >}}
{{< tab name="Command line" >}}
```bash
docker exec sftp fail2ban-client status sshd
```

The address appears under `Banned IP list`. Lift the ban with `docker exec sftp fail2ban-client set sshd unbanip <address>`.
{{< /tab >}}
{{< /tabs >}}

## Next

- Learn the admin web UI's pages: [How To Use The Admin Web UI](../../how-to/use-the-web-ui/).
- Let more people into the file browser: [How To Use The File Browser](../../how-to/use-the-file-browser/).
- Hash Alice's password instead of storing it in plain text: [How To Use Hashed Passwords](../../how-to/use-hashed-passwords/).
- Hold sign-ins from places an account has not used: [How To Hold Unusual Sign-ins](../../how-to/hold-unusual-sign-ins/).
- Run it with the fewest privileges: [How To Harden The Container](../../how-to/harden-the-container/).
