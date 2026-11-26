---
title: How To Use Hashed Passwords
weight: 2
---

A hashed password keeps the plain password out of `/config` and out of `docker inspect`. The container stores the hash as given and never sees the plain text.

## Set a hashed password

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Every password set in the web UI is saved as a yescrypt hash; the password itself is never written. Open the account, choose **Set a new password** under **Password**, type it twice, and choose **Save and apply**.

![The password section of an account](/screenshots/account-password.png)
{{< /tab >}}
{{< tab name="Command line" >}}
The image includes `mkpasswd`. Without a password argument it prompts, so the password never reaches your shell history:

```bash
docker run --rm -it markusmcnugen/sftp mkpasswd -m yescrypt
```

It prints one line, the hash, starting with `$y$`. yescrypt is the scheme Debian 13 uses for its own accounts. Any hash that `crypt(3)` understands also works, such as SHA-512 from `openssl passwd -6`.

Put the hash in the password field and add `:e` after it:

```text
carol:$y$j9T$Y3oP...:e:1003
```

The entrypoint warns when a field is marked `:e` but does not begin with `$`, because such a value can never match a password.
{{< /tab >}}
{{< /tabs >}}

## Hash the passwords already in users.conf

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
When `users.conf` holds plain-text passwords, the **Accounts** page says how many, and **Hash passwords** replaces each with its yescrypt hash in one step. The accounts keep the same passwords.

![The Accounts page offering to hash four plain-text passwords](/screenshots/accounts.png)
{{< /tab >}}
{{< tab name="Command line" >}}
Make a hash of each password with `mkpasswd`, as above, put it in place of the password with `:e` after it, and run `docker exec sftp entrypoint apply`.
{{< /tab >}}
{{< /tabs >}}

## In a Compose file

Compose treats `$` as the start of a variable, so write each `$` in a hash as `$$`:

```yaml
environment:
  SFTP_USERS: "carol:$$y$$j9T$$Y3oP...:e:1003"
```

A hash in `users.conf` or in a secrets file needs no escaping.
