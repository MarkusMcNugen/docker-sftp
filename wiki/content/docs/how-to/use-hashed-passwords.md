---
title: How To Use Hashed Passwords
weight: 2
---

A hashed password keeps the plain password out of `/config` and out of `docker inspect`. The container stores it as given and never sees the plain text.

## Make a hash

The image includes `mkpasswd`. Without a password argument it prompts, so the password never reaches your shell history:

```bash
docker run --rm -it markusmcnugen/sftp mkpasswd -m yescrypt
```

It prints one line, the hash, starting with `$y$`. yescrypt is the scheme Debian 13 uses for its own accounts. Any hash that `crypt(3)` understands also works, such as SHA-512 from `openssl passwd -6`.

## Use it

Put the hash in the password field and add `:e` after it:

```text
carol:$y$j9T$Y3oP...:e:1003
```

The entrypoint warns at start when a field is marked `:e` but does not begin with `$`, because such a value can never match a password.

## In a Compose file

Compose treats `$` as the start of a variable, so write each `$` in a hash as `$$`:

```yaml
environment:
  SFTP_USERS: "carol:$$y$$j9T$$Y3oP...:e:1003"
```

A hash in `users.conf` or in a secrets file needs no escaping.
