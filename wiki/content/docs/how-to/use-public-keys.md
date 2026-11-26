---
title: How To Use Public Keys
weight: 3
---

## Add a key

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
1. Open the account from **Accounts**.
2. Under **Public keys**, paste the user's public key, the contents of their `.pub` file, into **Add keys**. Paste several keys one per line.
3. Choose **Add keys**. The key works at once.

The section lists each key with its type, fingerprint and comment, and removes any one of them.

![An account's public keys](/screenshots/account-keys.png)

Keys added here are written to `/config/userkeys/<name>/webui.pub`, one of the files the command line uses, so both ways see the same keys.
{{< /tab >}}
{{< tab name="Command line" >}}
Copy the user's public key, the `.pub` file, into `/config/userkeys/` named after the account:

```text
/config/userkeys/bob.pub
```

For several keys, either put one per line in that file, or make a folder with one file per key:

```text
/config/userkeys/bob/laptop.pub
/config/userkeys/bob/phone.pub
```

Both are read, so a user can have keys in each. Apply the change to the running server:

```bash
docker exec sftp entrypoint apply
```

The log shows the fingerprint of every installed key, for example:

```text
entrypoint: user bob: key 256 SHA256:... bob@laptop (ED25519)
```
{{< /tab >}}
{{< /tabs >}}

A file that holds no valid key brings a warning naming the file, and an account with neither a password nor a key brings a warning that it cannot log in.

## Revoke a key

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Open the account, and under **Public keys** remove the key. It is removed from whichever of the account's key files holds it, and stops working at once.
{{< /tab >}}
{{< tab name="Command line" >}}
Delete the key from its file, or delete the file, and run `docker exec sftp entrypoint apply`. The key stops working at once, because the list is rebuilt from `/config/userkeys` each time.
{{< /tab >}}
{{< /tabs >}}

## Where keys go

Keys are installed as `/etc/ssh/authorized_keys/<name>`, owned by root, outside every jail. A user cannot add, change or remove a key through SFTP, and `~/.ssh/authorized_keys` inside a jail is not read. Windows line endings in a key file are removed.

## Key types

Ed25519, ECDSA, security-key (`sk-`) and RSA keys of at least 2048 bits are accepted. RSA signatures use SHA-2; the SHA-1 `ssh-rsa` signature is refused, so a client too old for `rsa-sha2-256` needs an Ed25519 key instead.
