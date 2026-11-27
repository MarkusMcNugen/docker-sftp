---
title: How To Hold Unusual Sign-ins
weight: 17
---

The sign-in check learns where each account signs in from. Once it has seen enough, it holds a sign-in from a place the account has not used, or from one too far from its last sign-in to have traveled there in time, until an admin approves it. When one account's sign-ins fail from several addresses in a short time, as in a password spray from bots that keep changing address, it locks the account to the networks it signed in from before: its own people keep signing in, and the spray is refused whatever passwords it tries.

The check runs while the admin web UI is on.

## What it checks

The check runs once a sign-in has the right password, key or code, so a wrong one stays an ordinary failed sign-in for fail2ban.

- SFTP sign-ins, rsync over SSH among them; sshd asks the check through PAM.
- File browser sign-ins, after the second factor.
- Not admins' sign-ins to the web UI.

A held or refused sign-in does not go ahead. An SFTP client is told why and disconnected, and the file browser shows the reason. Neither counts as a failed sign-in, so fail2ban does not ban someone waiting for approval, and neither counts toward a lockdown. The **Activity** log lists them as held or refused.

Loopback, private and link-local addresses always pass, unless the account is locked down. An address the country database does not place counts as one place of its own.

## How it learns

The check learns from the sign-in history the web UI keeps, the sign-ins recorded before the check existed included.

- Every sign-in that goes ahead, and every held one an admin approves, adds its country and its network to the account's profile: the /24 for IPv4, the /64 for IPv6.
- Holds start once an account has 5 such sign-ins, the first of them at least 7 days old. Until then every sign-in goes through and is learned.
- Impossible travel compares a sign-in with the account's last one: the distance between their countries, from the nearest point of one to the nearest point of the other, over the time between them. Above 750 km/h the sign-in is held. Neighboring countries are 0 km apart, so crossing a border is never impossible travel.

Countries come from the same database as the country rules ([Where countries come from](../block-countries/#where-countries-come-from)), and distances from Natural Earth's country borders.

## Approve or reject a held sign-in

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
A held sign-in shows on the **Bans** page, in the **Held sign-ins** card, and the **Status** page says how many are waiting. For each one:

- **Approve** adds its place to the account, so the next sign-in from there goes through. Ask the person to sign in again.
- **Reject** leaves its place out; another sign-in from there is held again.
- **Reject and ban** also bans its address on every port.

Sign-ins tried again from the same address while one waits stay a single entry.

![The Held sign-ins card on the Bans page](/screenshots/bans-held.png)
{{< /tab >}}
{{< tab name="Command line" >}}
Held sign-ins are decided on the web UI's **Bans** page, since the check runs only while the web UI is on. The auth log, which the web UI's **Logs** page shows, records each held or refused sign-in:

```
sftp-helper[812]: held the sign-in of alice from 198.51.100.40 for an admin's approval: New place: the account has not signed in from here
```
{{< /tab >}}
{{< /tabs >}}

## Password sprays

- Failed sign-ins to one account from 3 addresses within 60 minutes lock it down.
- While it is locked down, only the networks of its approved sign-ins can sign in to it. Every other sign-in is refused, even with the right password.
- The lockdown ends once no sign-in to the account has failed for 24 hours, or when an admin lifts it with **Lift the lockdown** in the **Locked accounts** card on the **Bans** page. Failed sign-ins from before a lift stop counting toward a lockdown.

![The Locked accounts card on the Bans page](/screenshots/bans-locked.png)

## Change the thresholds

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
The **SFTP server** card on the **Settings** page sets all six: **Sign-ins learned before holds start**, **Days learned before holds start**, **Impossible travel, in km/h**, **Failing addresses that lock an account**, **Within, in minutes** and **Lockdown ends after, in hours without a failure**.
{{< /tab >}}
{{< tab name="Command line" >}}
Set them in the environment, or as `NAME=value` lines in `/config/sshd/settings.conf`, which the check reads at each sign-in:

```yaml
    environment:
      SIGNIN_TRAVEL_KMH: "900"
```

A value set in the environment wins over `settings.conf` and over the Settings page.
{{< /tab >}}
{{< /tabs >}}

| Setting | Default | What it sets |
|---|---|---|
| `SIGNIN_LEARN_SIGNINS` | `5` | Sign-ins an account needs before holds start |
| `SIGNIN_LEARN_DAYS` | `7` | Days from an account's first sign-in before holds start |
| `SIGNIN_TRAVEL_KMH` | `750` | The speed, in km/h, above which a sign-in from another country counts as impossible travel |
| `SIGNIN_SPRAY_ADDRESSES` | `3` | Addresses whose failed sign-ins to one account lock it down |
| `SIGNIN_SPRAY_MINUTES` | `60` | The window, in minutes, those failures fall within |
| `SIGNIN_LOCKDOWN_HOURS` | `24` | Hours without a failed sign-in that end a lockdown |

## Where it does not run

- With your own `/config/sshd/sshd_config`, which replaces the built-in sshd configuration, SFTP sign-ins are not checked, and the log says so at start. File browser sign-ins still are.
- With the admin web UI off, nothing is checked.
