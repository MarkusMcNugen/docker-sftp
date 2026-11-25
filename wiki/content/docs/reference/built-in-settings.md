---
title: Built-in Settings
weight: 5
---

## sshd

Read from `sshd -T` in a running container with no overrides:

```text
port 22
logingracetime 30
maxauthtries 4
clientaliveinterval 120
clientalivecountmax 3
requiredrsasize 2048
permitrootlogin no
pubkeyauthentication yes
passwordauthentication yes
compression no
disableforwarding yes
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
macs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
forcecommand internal-sftp
chrootdirectory %h
kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256
loglevel VERBOSE
authorizedkeysfile /etc/ssh/authorized_keys/%u
allowgroups sftpusers
maxstartups 10:30:60
persourcepenalties crash:90 authfail:5 noauth:1 grace-exceeded:10 refuseconnection:10 max:600 min:15 max-sources4:65536 max-sources6:65536 overflow:permissive overflow6:permissive
```

Also set: `KbdInteractiveAuthentication no`, `HostbasedAuthentication no`, `UsePAM no`, `PermitTTY no`, `PermitTunnel no`, `PermitUserRC no`, `PermitUserEnvironment no`, `UseDNS no`, `SyslogFacility AUTH`. The group-exchange moduli file holds only moduli of at least 3072 bits.

`SFTP_CRYPTO_POLICY=strict` changes one line:

```text
macs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
```

Host keys: `/config/sshd/keys/ssh_host_ed25519_key` and `ssh_host_rsa_key` (4096 bits).

## fail2ban

From `/etc/fail2ban/jail.d/00-sftp.conf` and `fail2ban.d/00-sftp.conf`:

| Setting | Value |
|---|---|
| Jail | `sshd`, filter mode `normal`, backend `polling`, log `/var/log/auth.log` |
| `maxretry` / `findtime` | 5 failures within 10 minutes |
| `bantime` | 1 hour |
| `bantime.increment` / `bantime.maxtime` | each repeat ban doubles, up to 1 week |
| `banaction` | `iptables-allports`: every port of the address |
| `ignoreip` | `127.0.0.1/8 ::1` |
| `dbfile` / `dbpurgeage` | `/config/fail2ban/fail2ban.sqlite3`, history kept 8 days |
| `logtarget` | the container log |

## Accounts

| Setting | Value |
|---|---|
| Shell | `/usr/sbin/nologin` |
| Groups | primary gid from the account line (default 100), plus `sftpusers` |
| Password hashing | yescrypt, for plain-text passwords |
| Upload umask | `022` unless `SFTP_UMASK` sets another |
