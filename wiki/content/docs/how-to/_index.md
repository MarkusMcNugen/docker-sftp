---
title: How-to
weight: 2
sidebar:
  open: true
---

Task-oriented recipes. Each page solves one concrete problem and assumes the basics from [Tutorials](../tutorials/).

{{< cards >}}
  {{< card link="add-users/" title="How To Add And Change Users" subtitle="users.conf, SFTP_USERS, a secrets file, and what a restart changes." >}}
  {{< card link="use-hashed-passwords/" title="How To Use Hashed Passwords" subtitle="mkpasswd in the image, the :e marker, and Compose escaping." >}}
  {{< card link="use-public-keys/" title="How To Use Public Keys" subtitle="One or many keys per user, where they are installed, and revoking one." >}}
  {{< card link="share-host-directories/" title="How To Share Host Directories" subtitle="Bind mounts inside a jail, ownership, read-only mounts, and folders shared by several users." >}}
  {{< card link="change-sshd-settings/" title="How To Change sshd Settings" subtitle="Drop-in files, a read-only account, a different port, and the strict crypto policy." >}}
  {{< card link="tune-fail2ban/" title="How To Tune fail2ban" subtitle="Ban times, trusted addresses, unbanning, and your own filters." >}}
  {{< card link="log-transfers/" title="How To Log Transfers" subtitle="A log line for every upload, download, rename and delete." >}}
  {{< card link="allow-rsync/" title="How To Allow rsync" subtitle="rsync over SSH for chosen accounts, inside their jails, and nothing else." >}}
  {{< card link="harden-the-container/" title="How To Harden The Container" subtitle="The minimal capability set, no-new-privileges, and log rotation." >}}
  {{< card link="run-on-unraid/" title="How To Run It On Unraid" subtitle="The template settings, the extra parameters, and appdata permissions." >}}
  {{< card link="upgrade-from-1x/" title="How To Upgrade From 1.x" subtitle="What happens to an existing /config, and what to move by hand." >}}
  {{< card link="build-and-test/" title="How To Build And Test The Image" subtitle="Building locally, the integration suite, and running some scenarios only." >}}
  {{< card link="fix-a-failure/" title="How To Fix A Failure" subtitle="What each failure means, keyed by the message you see." >}}
{{< /cards >}}
