# syntax=docker/dockerfile:1

# Debian 13 (trixie). The scheduled CI build rebuilds on the latest point
# release every week, so security updates reach the image without a commit.
ARG DEBIAN_TAG=trixie-slim
FROM debian:${DEBIAN_TAG}

LABEL org.opencontainers.image.title="sftp" \
      org.opencontainers.image.description="Hardened OpenSSH SFTP server with chroot jails and fail2ban" \
      org.opencontainers.image.source="https://github.com/MarkusMcNugen/docker-sftp" \
      org.opencontainers.image.licenses="MIT"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG DEBIAN_FRONTEND=noninteractive

# whois provides mkpasswd, for hashing passwords to put in users.conf.
# systemd-standalone-sysusers satisfies openssh-server's sysusers dependency
# without installing systemd itself (17 MB).
# Group-exchange moduli under 3072 bits are dropped from /etc/ssh/moduli.
RUN apt-get update \
 && apt-get -y upgrade \
 && apt-get -y install --no-install-recommends \
        fail2ban \
        iptables \
        openssh-server \
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
 && groupadd --system sftpusers

COPY rootfs/ /

# Build contexts from Windows carry no Unix modes, so every mode is set here.
# The pristine copies under /usr/local/share/sftp are what the entrypoint
# restores on each start. The build fails if rsyslog or fail2ban reject
# the shipped configuration.
RUN chmod 0644 /etc/ssh/sshd_config /etc/rsyslog.conf \
        /etc/fail2ban/jail.d/00-sftp.conf /etc/fail2ban/fail2ban.d/00-sftp.conf \
        /usr/local/lib/sftp/legacy-defaults.sha256 \
 && chmod 0755 /usr/local/bin/entrypoint /usr/local/bin/healthcheck \
 && install -d -m 0755 /usr/local/share/sftp \
 && cp /etc/ssh/sshd_config /usr/local/share/sftp/sshd_config \
 && cp -a /etc/fail2ban /usr/local/share/sftp/fail2ban \
 && ln -s /usr/local/bin/entrypoint /entrypoint \
 && rsyslogd -N1 -f /etc/rsyslog.conf \
 && touch /var/log/auth.log \
 && fail2ban-client --test >/dev/null \
 && rm /var/log/auth.log

VOLUME ["/config"]
EXPOSE 22

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]
