---
title: How To Use Public Keys
weight: 3
---

## Add a key

Copy the user's public key, the `.pub` file, into `/config/userkeys/` named after the account:

```text
/config/userkeys/bob.pub
```

For several keys, either put one per line in that file, or make a folder with one file per key:

```text
/config/userkeys/bob/laptop.pub
/config/userkeys/bob/phone.pub
```

Both are read, so a user can have keys in each. Restart the container to apply a change.

At start the log shows the fingerprint of every installed key, for example:

```text
entrypoint: user bob: key 256 SHA256:... bob@laptop (ED25519)
```

A file that contains no valid key produces a warning naming the file, and an account with neither a password nor a key produces a warning that it cannot log in.

## Where keys go

Keys are installed as `/etc/ssh/authorized_keys/<name>`, owned by root, outside every jail. A user cannot add, change or remove a key through SFTP, and `~/.ssh/authorized_keys` inside a jail is not read. Windows line endings in a key file are removed.

## Revoke a key

Delete the key from its file, or delete the file, and restart. The key stops working at once, because the list is rebuilt from `/config/userkeys` on every start.

## Key types

Ed25519, ECDSA, security-key (`sk-`) and RSA keys of at least 2048 bits are accepted. RSA signatures use SHA-2; the SHA-1 `ssh-rsa` signature is refused, so a client too old for `rsa-sha2-256` needs an Ed25519 key instead.
