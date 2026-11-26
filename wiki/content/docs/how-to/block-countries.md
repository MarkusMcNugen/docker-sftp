---
title: How To Block Countries
weight: 16
---

The country rules drop new connections from chosen countries, or from every country but chosen ones, before they reach sshd, the admin web UI or the file browser. They are off until you turn them on.

## Turn them on

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
On the **Bans** page, the **Countries** card sets the rule, **Block listed countries** or **Allow only listed countries**, and the countries it lists. Add or remove countries, then choose **Save and apply**. The chart beside the list shows where failed logins came from in the last 24 hours.

![The Countries card on the Bans page](/screenshots/bans-countries.png)
{{< /tab >}}
{{< tab name="Command line" >}}
Set them in the environment, or as `NAME=value` lines in `/config/sshd/settings.conf` and then run `docker exec sftp entrypoint apply`:

```yaml
    environment:
      SFTP_COUNTRY_RULE: "block"
      SFTP_COUNTRIES: "CN RU"
```

A value set in the environment wins over `settings.conf` and over the Countries card.
{{< /tab >}}
{{< /tabs >}}

| Rule | Drops new connections from |
|---|---|
| `off` | nothing; the default |
| `block` | the countries in `SFTP_COUNTRIES` |
| `allow` | every country not in `SFTP_COUNTRIES`, and addresses in no country |

`SFTP_COUNTRIES` takes two-letter country codes separated by spaces or commas. Its default, `CN IN BR RU VN`, is a starting list for `block`; `allow` with no country is refused, since it would close every guarded port.

## What they guard

The rules guard sshd's ports, and the admin web UI's and the file browser's ports when those are on. Connections already open are left alone, and so are other ports. These addresses always pass:

- loopback, and the private and link-local ranges;
- the networks in `WEBUI_TRUSTED_NETWORKS`;
- fail2ban's never-ban list, which the Rules card on the Bans page edits. A host name there cannot be exempted, and the log says which.

## How they are enforced

The rules are loaded into an nftables table, `inet sftp_countries`, in the container's network namespace, which needs `--cap-add NET_ADMIN`. Without it the firewall refuses them: the Countries card marks them **Not enforced** and says why, and the log warns at start. The admin web UI and the file browser also check every request against the rules themselves, behind a reverse proxy too, where they read the client's address from `X-Forwarded-For` sent by `WEBUI_TRUSTED_PROXIES`.

Long lists load in batches small enough for a container in a user namespace, such as under rootless Podman, and a change takes effect in one step: the old lists stay in force until the new ones are complete.

## Where countries come from

The image carries DB-IP's IP to Country Lite database, refreshed by its weekly rebuild. For MaxMind GeoLite2 instead, create a free MaxMind account and a license key, then:

{{< tabs >}}
{{< tab name="Web UI" selected=true >}}
Enter the account ID and license key in the **Locations** card on the **Settings** page. They are kept root-only in `/config/geoip/maxmind.conf`. **Remove** deletes a key saved there and GeoLite2 with it, and the rules go back to DB-IP Lite.

![The Locations card on the Settings page](/screenshots/settings-locations.png)
{{< /tab >}}
{{< tab name="Command line" >}}
Set both in the environment:

```yaml
    environment:
      MAXMIND_ACCOUNT_ID: "123456"
      MAXMIND_LICENSE_KEY: "..."
```
{{< /tab >}}
{{< /tabs >}}

The server downloads GeoLite2 into `/config/geoip/`, checks every 6 hours, fetches a new copy once its copy is 3 days old, and loads the rules again with it.
