---
title: Reference
weight: 4
sidebar:
  open: true
---

Exact facts, for looking up rather than reading through.

{{< cards >}}
  {{< card link="environment-variables/" title="Environment Variables" subtitle="Every variable the container reads, its default, and what it changes." >}}
  {{< card link="users-conf/" title="users.conf" subtitle="The account line grammar, field by field, with every rule the entrypoint enforces." >}}
  {{< card link="config-volume/" title="The /config Volume" subtitle="Every path the container reads or writes, and when." >}}
  {{< card link="commands/" title="Commands" subtitle="The entrypoint, healthcheck, mkpasswd and fail2ban-client: arguments, output and exit codes." >}}
  {{< card link="built-in-settings/" title="Built-in Settings" subtitle="The effective sshd and fail2ban settings the image ships with." >}}
  {{< card link="log-messages/" title="Log Messages" subtitle="What the entrypoint, sshd, fail2ban and transfer logging print, with real examples." >}}
{{< /cards >}}
