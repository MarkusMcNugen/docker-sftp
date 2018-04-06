FROM phusion/baseimage

MAINTAINER MarkusMcNugen
# Forked from atmoz for unRAID

VOLUME /config

# Steps done in one RUN layer:
# - Install packages
# - OpenSSH needs /var/run/sshd to run
# - Remove generic host keys, entrypoint generates unique keys
RUN apt-get update && \
    apt-get -y install openssh-server fail2ban && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/run/sshd && \
    rm -f /etc/ssh/ssh_host_*key*

COPY entrypoint /
RUN chmod +x /entrypoint

ADD fail2ban /etc/default/fail2ban
ADD sshd /etc/default/sshd

EXPOSE 22

ENTRYPOINT ["/entrypoint"]
