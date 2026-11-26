# syntax=docker/dockerfile:1

# Debian 13 (trixie). The scheduled CI build rebuilds on the latest point
# release every week, so security updates reach the image without a commit.
ARG DEBIAN_TAG=trixie-slim
ARG RUST_TAG=1.100.0-slim-trixie

# The web UI and its helper are compiled on the build machine for the
# target architecture, so an arm64 image needs no emulated compiler.
FROM --platform=$BUILDPLATFORM rust:${RUST_TAG} AS webui
ARG TARGETARCH
ARG BUILDARCH
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /src
RUN case "$TARGETARCH" in \
        amd64) triple=x86_64-unknown-linux-gnu ;; \
        arm64) triple=aarch64-unknown-linux-gnu ;; \
        *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && printf '%s\n' "$triple" >/triple \
 && if [[ $TARGETARCH != "$BUILDARCH" ]]; then \
        apt-get update \
        && apt-get -y install --no-install-recommends "gcc-${triple%%-*}-linux-gnu" "libc6-dev-${TARGETARCH}-cross" \
        && rm -rf /var/lib/apt/lists/*; \
    fi \
 && rustup target add "$triple"
COPY webui/ ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    triple=$(</triple) \
 && if [[ $TARGETARCH != "$BUILDARCH" ]]; then \
        linker=CARGO_TARGET_${triple^^}_LINKER \
        && export "${linker//-/_}=${triple%%-*}-linux-gnu-gcc"; \
    fi \
 && cargo build --release --locked --target "$triple" \
 && install -D -m 0755 "target/$triple/release/sftp-webui" /out/sftp-webui \
 && install -D -m 0755 "target/$triple/release/sftp-helper" /out/sftp-helper

# DB-IP Lite, the country database the country rules read unless a MaxMind
# key is given: this month's, or last month's until this month's appears.
# CC BY 4.0, credited "IP Geolocation by DB-IP" with a link to db-ip.com.
FROM --platform=$BUILDPLATFORM debian:${DEBIAN_TAG} AS geo
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update \
 && apt-get -y install --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && month=$(date -u +%Y-%m) \
 && previous=$(date -u -d "${month}-01 -1 day" +%Y-%m) \
 && { curl -fsSL -o /tmp/dbip.mmdb.gz "https://download.db-ip.com/free/dbip-country-lite-${month}.mmdb.gz" \
      || curl -fsSL -o /tmp/dbip.mmdb.gz "https://download.db-ip.com/free/dbip-country-lite-${previous}.mmdb.gz"; } \
 && gunzip /tmp/dbip.mmdb.gz \
 && install -D -m 0644 /tmp/dbip.mmdb /out/dbip-country-lite.mmdb

FROM debian:${DEBIAN_TAG}

LABEL org.opencontainers.image.title="sftp" \
      org.opencontainers.image.description="Hardened OpenSSH SFTP server with chroot jails, fail2ban and an optional admin web UI" \
      org.opencontainers.image.source="https://github.com/MarkusMcNugen/docker-sftp" \
      org.opencontainers.image.licenses="MIT"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG DEBIAN_FRONTEND=noninteractive

# whois provides mkpasswd, for hashing passwords to put in users.conf.
# systemd-standalone-sysusers satisfies openssh-server's sysusers dependency
# without installing systemd itself (17 MB).
# Group-exchange moduli under 3072 bits are dropped from /etc/ssh/moduli.
# USERGROUPS_ENAB no keeps userdel from deleting a group that shares the
# name of a removed account.
# The web UI runs as sftp-webui, uid and gid 980, and the file browser as
# sftp-files, uid and gid 981; accounts may use neither.
RUN apt-get update \
 && apt-get -y upgrade \
 && apt-get -y install --no-install-recommends \
        fail2ban \
        iptables \
        nftables \
        openssh-server \
        rsync \
        rsyslog \
        systemd-standalone-sysusers \
        tini \
        tzdata \
        whois \
 && rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log /var/cache/debconf/*-old \
 && rm -rf /etc/rsyslog.d && install -d -m 0755 /etc/rsyslog.d \
 && rm -f /etc/ssh/ssh_host_*key* /etc/fail2ban/jail.d/defaults-debian.conf \
 && awk '$5 >= 3071' /etc/ssh/moduli >/etc/ssh/moduli.strong \
 && mv /etc/ssh/moduli.strong /etc/ssh/moduli \
 && sed -i 's/^USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' /etc/login.defs \
 && groupadd --system sftpusers \
 && groupadd --system --gid 980 sftp-webui \
 && useradd --system --uid 980 --gid 980 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "sftp web UI" sftp-webui \
 && groupadd --system --gid 981 sftp-files \
 && useradd --system --uid 981 --gid 981 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "sftp file browser" sftp-files

COPY rootfs/ /
COPY --from=webui /out/sftp-webui /usr/local/bin/sftp-webui
COPY --from=webui /out/sftp-helper /usr/local/libexec/sftp/sftp-helper
COPY --from=geo /out/dbip-country-lite.mmdb /usr/local/share/sftp/geo/dbip-country-lite.mmdb

# Build contexts from Windows carry no Unix modes, and one made with a umask
# of 002 has group-writable directories, which sshd refuses on the path to
# the authorized keys; so every mode is set here, the directories' too.
# The pristine copies under /usr/local/share/sftp are what the entrypoint
# restores on each start. The build fails if rsyslog or fail2ban reject
# the shipped configuration.
RUN chmod 0755 / /etc /etc/ssh /etc/fail2ban /etc/fail2ban/fail2ban.d /etc/fail2ban/filter.d /etc/fail2ban/jail.d \
        /usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/sftp /usr/local/libexec /usr/local/libexec/sftp \
 && chmod 0644 /etc/ssh/sshd_config /etc/rsyslog.conf \
        /etc/fail2ban/jail.d/00-sftp.conf /etc/fail2ban/fail2ban.d/00-sftp.conf \
        /etc/fail2ban/filter.d/sftp-webui.conf \
        /usr/local/lib/sftp/legacy-defaults.sha256 \
 && chmod 0755 /usr/local/bin/entrypoint /usr/local/bin/healthcheck \
        /usr/local/libexec/sftp/rsync-gate \
 && install -d -m 0755 /usr/local/share/sftp \
 && cp /etc/ssh/sshd_config /usr/local/share/sftp/sshd_config \
 && cp -a /etc/fail2ban /usr/local/share/sftp/fail2ban \
 && ln -s /usr/local/bin/entrypoint /entrypoint \
 && rsyslogd -N1 -f /etc/rsyslog.conf \
 && touch /var/log/auth.log \
 && fail2ban-client --test >/dev/null \
 && rm /var/log/auth.log \
 && sftp-webui --version

VOLUME ["/config"]
EXPOSE 22 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]
