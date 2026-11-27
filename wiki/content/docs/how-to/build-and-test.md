---
title: How To Build And Test The Image
weight: 11
---

## Build

```bash
git clone https://github.com/MarkusMcNugen/docker-sftp
cd docker-sftp
docker build -t sftp .
```

With Podman, add `--format docker`; the default OCI format drops the image's health check. The build fails if rsyslog or fail2ban rejects the shipped configuration.

## Test

```bash
tests/run-tests.sh sftp                  # an image you built
tests/run-tests.sh                       # builds localhost/sftp:test first
ENGINE=podman tests/run-tests.sh sftp    # Podman instead of Docker
SCENARIOS="main options" tests/run-tests.sh sftp
```

The suite starts real servers on a private network and drives them with OpenSSH clients from other containers. It needs an engine that can grant `NET_ADMIN`. Each check prints `ok`, `not ok` or `skip`, and the script exits non-zero if any check fails.

| Scenario | Covers |
|---|---|
| `main` | password, hash and key logins, the jail, refused shells, forwarding and weak crypto, transfer logging, bans, and reconciliation across a restart |
| `crash` | the container stopping when sshd dies |
| `hardened` | the minimal capability set with `no-new-privileges` |
| `port` | `SFTP_PORT` and the health check following it |
| `options` | `SFTP_USERS_FILE`, `SFTP_UMASK`, `FAIL2BAN_ENABLED`, `TZ`, `SFTP_CRYPTO_POLICY=strict`, `SFTP_AUTH_LOG_MAX_BYTES` |
| `rotation` | a small auth log cap: rotation, rsyslog writing on, and bans from what is written after it |
| `rsync` | rsync through the jail, for accounts opted in on their line or by `SFTP_RSYNC_USERS`, and none for the rest |
| `perms` | permissions and controls from the options on account lines |
| `groups` | groups in `groups.conf`, and what members take from them |
| `countries` | the country rules: the nftables table, block and allow, the never-ban list, reloads and turning them off |
| `browser` | the file browser's own sshd: loopback only, its certificates only, each account's permissions |
| `apply` | `entrypoint apply` taking effect while the server runs, with open sessions kept |
| `webui` | the admin web UI and the file browser, driven over HTTPS by `tests/webui_driver.py` |
| `legacy` | untouched and edited 1.x configuration in `/config` |
| `reject` | configurations the entrypoint refuses, and running a command instead of the server |

## Lint

```bash
shellcheck -x rootfs/usr/local/bin/entrypoint rootfs/usr/local/bin/healthcheck tests/run-tests.sh
hadolint Dockerfile
cd webui && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked
```

The web UI is a Rust crate in `webui/`; it builds on Linux with Rust 1.100, and its tests run with `cargo test`.

## Screenshots

The screenshots in these docs and the README come from a demo server with made-up accounts, taken by the scripts in `tools/docs-screenshots/`. Its README says how to take them again for a release.

## Releases

`.github/workflows/release.yml` runs on a `v*` tag, every week, and by hand. It lints, runs the suite on a native x86 runner and a native arm64 runner, scans the image with Trivy, and publishes `linux/amd64` and `linux/arm64` images to Docker Hub and GHCR. The weekly run rebuilds the newest release tag, so Debian security updates reach the published image.
