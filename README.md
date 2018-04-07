[preview]: https://raw.githubusercontent.com/MarkusMcNugen/docker-templates/master/sftp/SFTP.png "SFTP"

![alt text][preview]

# SFTP with Fail2ban
Easy to use SFTP ([SSH File Transfer Protocol](https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol)) server with [OpenSSH](https://en.wikipedia.org/wiki/OpenSSH) and [Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) installed for extra hardening against brute force attacks. Forked from atmoz/sftp. 
This is an automated build linked with [phusion/baseimage](https://hub.docker.com/r/phusion/baseimage/).

# Docker Features
* Base: phusion/baseimage
* Size: 236MB
* Default hardened default ssh config coutesy of atmoz
* Fail2ban
* Optional config volume can be mounted for custom ssh and fail2ban configuration and easily viewing fail2ban log

# Run container from Docker registry
## Simplest docker run example
```
docker run -p 22:22 -d markusmcnugen/sftp foo:pass:::upload
```

User "foo" with password "pass" can login with sftp and upload files to a folder called "upload". No mounted directories or custom UID/GID. Later you can inspect the files and use `--volumes-from` to mount them somewhere else (or see next example).

## Sharing a directory from your computer without config volume mounted
Let's mount a directory and set UID:
```
docker run \
    -v /host/upload:/home/foo/upload \
    -p 2222:22 -d markusmcnugen/sftp \
    foo:pass:1001
```

## Sharing a directory from your computer with config volume mounted
```
docker run \
    -v /host/config/path:/config \
    -v /host/upload:/home/foo/upload \
    -p 2222:22 -d markusmcnugen/sftp \
    foo:pass:1001
```

### Logging in
The OpenSSH server runs by default on port 22, and in this example, we are forwarding the container's port 22 to the host's port 2222. To log in with the OpenSSH client, run: `sftp -P 2222 foo@<host-ip>`

## Store users in config
```
docker run \
    -v /host/config/path:/config \
    -v mySftpVolume:/home \
    -p 2222:22 -d markusmcnugen/sftp
```

/config/sshd/users.conf:
```
foo:123:1001:100
bar:abc:1002:100
baz:xyz:1003:100
```

## Encrypted password
Add `:e` behind password to mark it as encrypted. Use single quotes if using terminal.
```
'foo:$1$0G2g0GSt$ewU0t6GXG15.0hWoOX8X9.:e:1001'
```

Tip: you can use [atmoz/makepasswd](https://hub.docker.com/r/atmoz/makepasswd/) to generate encrypted passwords:  
`echo -n "your-password" | docker run -i --rm atmoz/makepasswd --crypt-md5 --clearfrom=-`

## Logging in with SSH keys
Place public keys with the users name in /config/userkeys directory. The keys will be matched against users names and copied to `.ssh/authorized_keys` for the user (you can't mount this file directly, because OpenSSH requires limited file permissions). In this example, we do not provide any password, so the user `foo` can only login with his SSH key.

## Providing your own SSH host key (recommended)
This container will generate new SSH host keys at first run in /config/sshd/keys. You can place your own sshd keys in this folder and they will be copied to /etc/ssh/ when the container runs.

Tip: you can generate your keys with these commands:

```
ssh-keygen -t ed25519 -f ssh_host_ed25519_key < /dev/null
ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key < /dev/null
```

## Execute custom scripts or applications
Put your programs in `/config/sshd/scripts` and it will automatically run when the container starts.
See next subsection for an example.

### Bindmount dirs from another location
If you are using `--volumes-from` or just want to make a custom directory available in user's home directory, you can add a script to `/config/sshd/scripts/` that bindmounts after container starts.
```
#!/bin/bash
# File mounted as: /config/sshd/scripts/bindmount.sh
# Just an example (make your own)

function bindmount() {
    if [ -d "$1" ]; then
        mkdir -p "$2"
    fi
    mount --bind $3 "$1" "$2"
}

# Remember permissions, you may have to fix them:
# chown -R :users /data/common

bindmount /data/admin-tools /home/admin/tools
bindmount /data/common /home/dave/common
bindmount /data/common /home/peter/common
bindmount /data/docs /home/peter/docs --read-only
```

**NOTE:** Using `mount` requires that your container runs with the `CAP_SYS_ADMIN` capability turned on. [See this answer for more information](https://github.com/atmoz/sftp/issues/60#issuecomment-332909232).

**Note:** The time when this image was last built can delay the availability of an OpenSSH release. Since this is an automated build linked with [phusion/baseimage](https://hub.docker.com/r/phusion/baseimage/), the build will depend on how often they push changes (out of my control). You can of course make this more predictable by cloning this repo and run your own build manually.

# Using Docker Compose:
```
sftp:
    image: markusmcnugen/sftp
    volumes:
        - /host/upload:/home/foo/upload
    ports:
        - "2222:22"
    command: foo:pass:1001
```
