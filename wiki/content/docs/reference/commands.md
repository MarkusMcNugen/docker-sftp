---
title: Commands
weight: 4
---

Every example below is real output from the image. Timestamps at the start of log lines are left out.

## The entrypoint

```text
docker run [options] markusmcnugen/sftp [account line ...]
docker run [options] markusmcnugen/sftp <command> [arguments ...]
```

Arguments shaped like an account line (a name, then `:`) are added to the accounts, and the server starts. Any other first argument is run in place of the server, with no setup:

```bash
docker run --rm markusmcnugen/sftp sh -c 'echo ran-instead'
```

```text
ran-instead
```

| Exit status | Meaning |
|---|---|
| 0 | Stopped by `docker stop` |
| 1 | A configuration error, or a service died (the log names which) |
| 3 | No account is configured anywhere |
| other | The status of the service that died, when it was not 0 |

A configuration error is one log line, printed before anything is created:

```text
$ docker run --rm markusmcnugen/sftp eve:pw:::../etc
entrypoint: fatal: user "eve": directory "../etc" may not contain . or ..
```

## healthcheck

```text
/usr/local/bin/healthcheck
```

Prints one line and exits 0 when healthy, 1 otherwise. Docker runs it every 30 s.

| Output | Exit | Meaning |
|---|---|---|
| `healthy` | 0 | sshd listens on every configured port and fail2ban, when enabled, is running |
| `not started yet` | 1 | the entrypoint has not reached the point of starting the services |
| `sshd is not listening on port 22` | 1 | the named port has no listening socket |
| `fail2ban is not running` | 1 | fail2ban's socket or process file is missing |
| `fail2ban (pid <pid>) is gone` | 1 | fail2ban's recorded process has exited |

```bash
docker inspect --format '{{.State.Health.Status}}' sftp
```

## mkpasswd

```text
mkpasswd -m yescrypt [password]
```

Prints a `crypt(3)` hash of the password, prompting for it when it is not given. From the `whois` package.

```text
$ docker run --rm markusmcnugen/sftp mkpasswd -m yescrypt changeme
$y$j9T$6IoIpga7qoVTKEtg7uOmk.$wqs4plcBkLh9AkLUNTXVh2MqiT4GaFcVqfk.9yQ.N/0
```

`mkpasswd -m help` lists the other schemes.

## fail2ban-client

Run inside the container with `docker exec sftp fail2ban-client ...`.

**`status sshd`**: the jail's counters and the banned addresses.

```text
Status for the jail: sshd
|- Filter
|  |- Currently failed:	1
|  |- Total failed:	6
|  `- File list:	/var/log/auth.log
`- Actions
   |- Currently banned:	1
   |- Total banned:	1
   `- Banned IP list:	10.89.0.3
```

**`get sshd banip`**: banned addresses, separated by spaces. With `--with-time`, one per line: the address, when the ban started, `+` the ban length in seconds, `=` when it ends.

**`set sshd unbanip <address>`**: lifts a ban and prints how many were lifted, `1` or `0`.

**`set sshd banip <address>`**: bans an address by hand.

**`get sshd bantime`**, **`findtime`**, **`maxretry`**: the jail's current values, in seconds and attempts:

```text
3600
600
5
```

**`get sshd actions`**: the ban action in use.

```text
The jail sshd has the following actions:
iptables-allports
```

## sftp and ssh from a client

`sftp -P <port> <name>@<host>` connects. `ssh` connects too, and is answered with:

```text
This service allows sftp connections only.
```

and exit status 1. A banned address gets `Connection refused`.
