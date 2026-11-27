"""Drives the admin web UI over HTTPS for tests/run-tests.sh.

    python3 webui_driver.py <base-url> <step> [args...]

Each step prints "ok <check>" or "not ok <check>: <why>" per check, and
keeps cookies and state in /tmp/webui-<name>.json between calls, so the
shell suite can interleave SFTP checks with web steps.
"""

import base64
import hashlib
import hmac
import html
import http.client
import io
import json
import re
import ssl
import struct
import sys
import tarfile
import time
import urllib.parse
import zipfile

BASE = sys.argv[1]
STEP = sys.argv[2]
ARGS = sys.argv[3:]
HOST = urllib.parse.urlparse(BASE).netloc
# The file browser listens on the same host, on its own port.
FILES_HOST = f"{urllib.parse.urlparse(BASE).hostname}:8444"


def state_path(name):
    return f"/tmp/webui-{name}.json"


def load(name):
    try:
        with open(state_path(name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"cookies": {}}


def save(name, st):
    with open(state_path(name), "w") as f:
        json.dump(st, f)


def check(name, ok, why=""):
    print(f"ok {name}" if ok else f"not ok {name}: {why}", flush=True)
    return ok


def skip(name, why):
    print(f"skip {name}: {why}", flush=True)


def request(st, method, path, form=None, headers=None, host=HOST, data=None, raw=False):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(host, context=ctx, timeout=120)
    h = {"Host": host, "Sec-Fetch-Site": "same-origin"}
    if st["cookies"]:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in st["cookies"].items())
    body = data
    if form is not None:
        body = urllib.parse.urlencode(form)
        h["Content-Type"] = "application/x-www-form-urlencoded"
    if headers:
        h.update(headers)
    conn.request(method, path, body=body, headers=h)
    res = conn.getresponse()
    body = res.read()
    text = body if raw else body.decode("utf-8", "replace")
    for value in res.headers.get_all("Set-Cookie") or []:
        pair = value.split(";", 1)[0]
        k, _, v = pair.partition("=")
        if "Max-Age=0" in value:
            st["cookies"].pop(k, None)
        else:
            st["cookies"][k] = v
    return res.status, res.headers, text


def hidden(text, name):
    m = re.search(r'name="%s" value="([^"]*)"' % re.escape(name), text)
    return m.group(1) if m else ""


def csrf(text):
    return hidden(text, "csrf")


def escaped(text, page):
    """True when `text` appears in `page` with its < and > escaped, as a
    named or a numeric character reference."""
    pattern = re.escape(text).replace("<", "&(?:lt|#60|#x3[cC]);").replace(">", "&(?:gt|#62|#x3[eE]);")
    return re.search(pattern, page) is not None


def unzipped(archive):
    """A zip file's files by name, and the first entry whose CRC is wrong or
    why it cannot be read at all; None when every entry checks out."""
    try:
        z = zipfile.ZipFile(io.BytesIO(archive))
        bad = z.testzip()
        return {i.filename: z.read(i.filename) for i in z.infolist() if not i.is_dir()}, bad
    except zipfile.BadZipFile as e:
        return {}, f"not a zip file: {e}"


def alerts(text):
    """The messages a page shows in its alerts, for a failed check's detail."""
    return " | ".join(html.unescape(m) for m in re.findall(r'class="alert-text">([^<]*)<', text))


def totp(secret_b32, at):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(at) // 30), hashlib.sha1).digest()
    o = digest[-1] & 15
    return "%06d" % ((struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def login(st, name, password, code=""):
    _, _, page = request(st, "GET", "/login")
    return request(st, "POST", "/login", {"login_token": hidden(page, "login_token"), "name": name, "password": password, "code": code})


def step_fresh():
    st = load("admin")
    status, headers, text = request(st, "GET", "/login")
    check("the login page says no admin exists yet", status == 200 and "No admin yet" in text, f"{status}")
    csp = headers.get("Content-Security-Policy", "")
    check("pages carry a strict Content-Security-Policy", "default-src 'none'" in csp and "script-src 'self'" in csp, csp)
    check("pages carry HSTS, nosniff, DENY framing and no referrer",
          headers.get("Strict-Transport-Security", "").startswith("max-age=")
          and headers.get("X-Content-Type-Options") == "nosniff"
          and headers.get("X-Frame-Options") == "DENY"
          and headers.get("Referrer-Policy") == "no-referrer", str(dict(headers)))
    check("pages are not cached", headers.get("Cache-Control") == "no-store", headers.get("Cache-Control", ""))
    status, _, text = request(st, "GET", "/setup?token=not-the-token")
    check("a wrong setup token is refused", status == 404 and "This link no longer works" in text, f"{status}")
    status, _, _ = request(st, "GET", "/accounts")
    check("pages need a session", status == 303, f"{status}")
    save("admin", st)


def step_setup(token, name, password):
    st = load("admin")
    _, _, page = request(st, "GET", f"/setup?token={token}")
    form = {"login_token": hidden(page, "login_token"), "token": token, "name": name, "password": "short", "confirm": "short"}
    status, _, text = request(st, "POST", "/setup", form)
    check("setup refuses a password under 12 characters", status == 422 and "at least 12" in text, f"{status}")
    _, _, page = request(st, "GET", f"/setup?token={token}")
    form.update(login_token=hidden(page, "login_token"), password=password, confirm=password)
    status, headers, _ = request(st, "POST", "/setup", form)
    check("setup creates the first admin and signs in", status == 303 and "__Host-sftp_session" in st["cookies"], f"{status}")
    check("the session cookie is Secure, HttpOnly and SameSite=Strict",
          any("__Host-sftp_session" in c and "Secure" in c and "HttpOnly" in c and "SameSite=Strict" in c
              for c in headers.get_all("Set-Cookie") or []), str(headers.get_all("Set-Cookie")))
    other = {"cookies": {}}
    status, _, _ = request(other, "GET", f"/setup?token={token}")
    check("the setup link works once", status == 303, f"{status}")
    save("admin", st)


def step_protections():
    st = load("admin")
    status, _, page = request(st, "GET", "/")
    check("the status page shows the host key fingerprints", status == 200 and "Server fingerprints" in page and "SHA256:" in page, f"{status}")
    status, _, text = request(st, "POST", "/settings", {"SFTP_UMASK": "002"})
    check("a change without the CSRF token is refused", status == 403 and "expired" in text, f"{status}")
    status, _, _ = request(st, "POST", "/settings", {"csrf": csrf(page), "SFTP_UMASK": "002"}, {"Sec-Fetch-Site": "cross-site"})
    check("a change from another site is refused", status == 403, f"{status}")


def step_create_account(name, password, preset="readonly"):
    st = load("admin")
    _, _, page = request(st, "GET", "/accounts/new")
    form = {"csrf": csrf(page), "name": name, "password_mode": "set", "password": password, "password2": password,
            "uid": "", "gid": "", "dirs": "up", "preset": preset, "web": "on"}
    status, headers, made = request(st, "POST", "/accounts/new", form)
    check(f"the UI creates the {preset} account {name}", status == 303 and headers.get("Location") == f"/accounts/{name}",
          f"{status} {headers.get('Location')} {alerts(made)}")
    _, _, text = request(st, "GET", f"/accounts/{name}")
    check(f"the account page shows the account as {preset}", f'value="{preset}" checked' in text, "")


def step_activity(account):
    st = load("admin")
    # The collector reads the event log once a second.
    for _ in range(20):
        status, _, text = request(st, "GET", f"/activity?account={account}")
        if status == 200 and 'data-kind="login_ok"' in text:
            break
        time.sleep(0.5)
    check("the Activity log shows an account's SFTP sign-in",
          status == 200 and 'data-kind="login_ok"' in text and f">{account}<" in text, f"{status}")
    status, _, text = request(st, "GET", "/activity")
    check("the People view shows the account that signed in",
          status == 200 and 'class="card person"' in text and f">{account}<" in text, f"{status}")


def step_sessions(account, address):
    st = load("admin")
    shown = f"<code>{address}</code>"
    # The collector reads the session's login within a second.
    for _ in range(20):
        status, _, text = request(st, "GET", "/")
        if status == 200 and shown in text:
            break
        time.sleep(0.5)
    check("the Status page opens while an SFTP session is open and lists it with its address",
          status == 200 and f">{account}<" in text and shown in text, f"{status} {alerts(text)}")
    status, _, text = request(st, "GET", "/sessions")
    check("the live session rows list the open session", status == 200 and shown in text, f"{status} {alerts(text)}")
    status, _, text = request(st, "GET", "/accounts")
    check("the Accounts page opens while an SFTP session is open", status == 200, f"{status} {alerts(text)}")
    status, _, text = request(st, "GET", f"/accounts/{account}")
    check("an account's page opens while its session is open and lists it",
          status == 200 and address in text, f"{status} {alerts(text)}")


def step_settings():
    st = load("admin")
    _, _, page = request(st, "GET", "/settings")
    status, _, _ = request(st, "POST", "/settings", {"csrf": csrf(page), "SFTP_UMASK": "027"})
    _, _, text = request(st, "GET", "/settings")
    check("settings are saved to settings.conf and applied", status == 303 and "Settings saved and applied" in text, f"{status}")
    check("the country rules are not on the Settings page", "SFTP_COUNTRY" not in text, "")
    check("the Settings page names the bundled country database and credits DB-IP",
          ">Locations<" in text and "DB-IP Lite</span>" in text and "IP Geolocation by DB-IP" in text, "")
    form = {"csrf": csrf(text), "account_id": "not-a-number", "license_key": "abcdef_123456"}
    request(st, "POST", "/settings/maxmind", form)
    _, _, text = request(st, "GET", "/settings")
    check("a malformed MaxMind account ID is refused before any download",
          "a MaxMind account ID is a number" in text and "DB-IP Lite</span>" in text, "")


def step_bans(address):
    st = load("admin")
    _, _, page = request(st, "GET", "/bans")
    request(st, "POST", "/bans/ban", {"csrf": csrf(page), "address": address})
    _, _, text = request(st, "GET", "/bans")
    check("an address banned in the UI is listed", address in text, "")
    check("the bans page reads the bundled country database and credits DB-IP",
          'data-label="Country"' in text and "IP Geolocation by DB-IP" in text, "")
    unread = re.search(r"database could not be read: ([^<]*)<", text)
    check("the bans page reads fail2ban's ban records", unread is None, unread.group(1) if unread else "")
    check("a ban made in the UI shows as an admin's", 'data-tip="Banned by an admin"' in text, "")
    request(st, "POST", "/bans/unban", {"csrf": csrf(text), "jail": "sshd", "address": address})
    _, _, text = request(st, "GET", "/bans")
    check("an address unbanned in the UI is gone", f">{address}<" not in text, "")
    status, _, text = request(st, "GET", "/bans?show=history")
    check("the ban history keeps a lifted ban, as an admin's",
          status == 200 and f">{address}<" in text and 'data-tip="Banned by an admin"' in text, f"{status}")


def step_files(name, access="readonly"):
    st = load("admin")
    _, _, page = request(st, "GET", f"/accounts/{name}")
    check("the account page shows its file browser sign-in, not set up yet", ">File browser<" in page and "Not set up" in page, "")
    request(st, "POST", f"/accounts/{name}/files-invite", {"csrf": csrf(page)})
    _, _, page = request(st, "GET", f"/accounts/{name}")
    link = re.search(r":8444/invite\?token=([A-Za-z0-9_-]+)", page)
    if not check("an admin makes a file browser sign-in link", link is not None, ""):
        return
    token = link.group(1)
    user = {"cookies": {}}
    status, _, page = request(user, "GET", f"/invite?token={token}", host=FILES_HOST)
    secret = hidden(page, "secret")
    check("the sign-in link opens the setup page", status == 200 and f"Welcome, {name}" in page and secret != "", f"{status}")
    password = "web-password-123"
    form = {"login_token": hidden(page, "login_token"), "token": token, "name": name, "secret": secret,
            "password": password, "confirm": password, "code": totp(secret, time.time())}
    status, _, page = request(user, "POST", "/invite", form, host=FILES_HOST)
    check("the link sets a web password and a second factor", status == 200 and "Your sign-in is ready" in page, f"{status}")
    status, _, again = request({"cookies": {}}, "GET", f"/invite?token={token}", host=FILES_HOST)
    check("a sign-in link works once", status == 404 and "This link no longer works" in again, f"{status}")
    form = {"login_token": hidden(page, "login_token"), "name": name, "password": password, "code": "000000"}
    status, _, page = request(user, "POST", "/login", form, host=FILES_HOST)
    check("a wrong code is refused", status == 401 and "Wrong code" in page, f"{status}")
    # Each code works once, so the sign-in uses the next step's.
    step = int(time.time() + 30) // 30
    form = {"login_token": hidden(page, "login_token"), "name": name, "password": password, "code": totp(secret, step * 30)}
    status, _, _ = request(user, "POST", "/login", form, host=FILES_HOST)
    save(f"files-{name}", {"cookies": {}, "secret": secret, "password": password, "step": step})
    status2, _, page = request(user, "GET", "/", host=FILES_HOST)
    check("the account signs in to the file browser",
          status == 303 and status2 == 200 and 'data-fm data-path="/"' in page and f'<span class="user-name">{name}</span>' in page,
          f"{status} {status2}")
    check("the file browser lists the account's folders over sftp", 'data-path="/up" data-name="up" data-kind="dir"' in page, "")
    status, _, page = request(user, "GET", "/?path=/up", host=FILES_HOST)
    check("a folder opens and lists its files", status == 200 and ">hello.txt<" in page, f"{status}")
    status, headers, body = request(user, "GET", "/download?path=/up/hello.txt", host=FILES_HOST)
    check("a file downloads through sftp", status == 200 and body == "hello from sftp\n"
          and "attachment" in headers.get("Content-Disposition", ""), f"{status} {body[:80]!r}")
    status, _, _ = request(user, "PUT", "/upload?path=/up/new.txt", data=b"new", host=FILES_HOST)
    check("an upload without the page's token is refused", status == 403, f"{status}")
    token = {"X-CSRF-Token": hidden(page, "csrf")}
    if access == "readonly":
        status, _, page = request(user, "POST", "/mkdir", {"csrf": hidden(page, "csrf"), "path": "/up", "name": "made"},
                                  host=FILES_HOST)
        check("the account's own permissions apply: a read-only account cannot make a folder",
              status == 422 and "may not do that" in page, f"{status}")
        status, _, text = request(user, "PUT", "/upload?path=/up/new.txt", data=b"new", host=FILES_HOST, headers=token)
        check("an upload into a read-only account is refused by the server", status == 422 and "may not do that" in text,
              f"{status} {text[:80]!r}")
    else:
        status, _, text = request(user, "PUT", "/upload?path=/up/new.txt", data=b"new" * 20000, host=FILES_HOST, headers=token)
        check("a file uploads through sftp, larger than a form may be", status == 200 and "Uploaded new.txt" in text,
              f"{status} {text[:80]!r}")
        _, _, body = request(user, "GET", "/download?path=/up/new.txt", host=FILES_HOST)
        check("the uploaded file reads back whole", body == "new" * 20000, f"{len(body)} characters")
        csrf_token = hidden(page, "csrf")
        request(user, "POST", "/rename", {"csrf": csrf_token, "path": "/up/new.txt", "name": "renamed.txt"}, host=FILES_HOST)
        request(user, "POST", "/mkdir", {"csrf": csrf_token, "path": "/up", "name": "made"}, host=FILES_HOST)
        _, _, page = request(user, "GET", "/?path=/up", host=FILES_HOST)
        check("a file renames and a folder is made",
              ">renamed.txt<" in page and 'data-path="/up/made"' in page and ">new.txt<" not in page, "")
        check("a hostile file name shows as text, never as markup",
              escaped("<img src=x onerror=alert(1)>.txt", page) and "<img src=x" not in page, "")
        request(user, "PUT", "/upload?path=/up/part.bin", data=b"a" * 1000, host=FILES_HOST, headers=token)
        status, _, text = request(user, "PUT", "/upload?path=/up/part.bin&offset=1000", data=b"b" * 500, host=FILES_HOST,
                                  headers=token)
        _, _, held = request(user, "GET", "/size?path=/up/part.bin", host=FILES_HOST)
        check("an upload that stopped goes on from where the server's copy ends", status == 200 and held == "1500",
              f"{status} {held!r} {text[:80]!r}")
        status, _, text = request(user, "PUT", "/upload?path=/up/part.bin&offset=10", data=b"c", host=FILES_HOST, headers=token)
        check("an upload does not go on from anywhere but the copy's end", status == 422 and "holds 1500 B" in text,
              f"{status} {text[:80]!r}")
        status, _, _ = request(user, "POST", "/mkdirs", {"path": "/up/deep/er"}, host=FILES_HOST, headers=token)
        status2, _, _ = request(user, "PUT", "/upload?path=/up/tree/a/b.txt&parents=true", data=b"leaf", host=FILES_HOST,
                                headers=token)
        check("an uploaded folder makes the folders it needs", status == 204 and status2 == 200, f"{status} {status2}")
        request(user, "POST", "/copy", [("csrf", csrf_token), ("folder", "/up"), ("path", "/up/tree"), ("to", "/up")],
                host=FILES_HOST)
        _, _, body = request(user, "GET", "/download?path=/up/tree%20copy/a/b.txt", host=FILES_HOST)
        check("a folder copies with everything in it, beside itself as a copy", body == "leaf", f"{body[:80]!r}")
        status, _, archive = request(user, "GET", "/zip?path=/up/tree", host=FILES_HOST, raw=True)
        files, bad = unzipped(archive)
        check("a folder downloads as a zip file holding everything in it",
              status == 200 and files == {"tree/a/b.txt": b"leaf"} and bad is None, f"{status} {sorted(files)} {bad}")
        status, _, archive = request(user, "POST", "/zip", [("csrf", csrf_token), ("folder", "/up"), ("path", "/up/hello.txt"),
                                                            ("path", "/up/tree")], host=FILES_HOST, raw=True)
        files, bad = unzipped(archive)
        check("chosen files and folders download as one zip file",
              status == 200 and files == {"hello.txt": b"hello from sftp\n", "tree/a/b.txt": b"leaf"} and bad is None,
              f"{status} {sorted(files)} {bad}")
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("inner/x.txt", "packed " * 1000)
            z.writestr("../evil.txt", "escape")
        request(user, "PUT", "/upload?path=/up/pack.zip", data=packed.getvalue(), host=FILES_HOST, headers=token)
        status, _, part = request(user, "GET", "/archive?path=/up/pack.zip", host=FILES_HOST)
        check("an archive lists its entries and marks one whose path would leave the folder",
              status == 200 and ">inner/x.txt<" in part and ">../evil.txt<" in part and "Not unpacked" in part, f"{status}")
        _, _, inner = request(user, "GET", "/archive/entry?path=/up/pack.zip&entry=0", host=FILES_HOST)
        check("one file of an archive downloads unpacked", inner == "packed " * 1000, f"{len(inner)} characters")
        status, _, page = request(user, "POST", "/archive/extract", {"csrf": csrf_token, "path": "/up/pack.zip"}, host=FILES_HOST)
        _, _, unpacked = request(user, "GET", "/download?path=/up/inner/x.txt", host=FILES_HOST)
        status2, _, _ = request(user, "GET", "/size?path=/evil.txt", host=FILES_HOST)
        check("an archive unpacks beside itself, and an entry that would leave the folder is refused",
              status == 422 and "evil.txt was not unpacked" in page and unpacked == "packed " * 1000 and status2 == 422,
              f"{status} {status2} {alerts(page)}")
        tarred = io.BytesIO()
        with tarfile.open(fileobj=tarred, mode="w:gz") as t:
            for entry, data, kind, link in [("tdir/t.txt", b"tarred " * 1000, tarfile.REGTYPE, ""),
                                             ("../tevil.txt", b"escape", tarfile.REGTYPE, ""),
                                             ("tdir/to-passwd", b"", tarfile.SYMTYPE, "/etc/passwd")]:
                info = tarfile.TarInfo(entry)
                info.type, info.linkname, info.size = kind, link, len(data)
                t.addfile(info, io.BytesIO(data))
        request(user, "PUT", "/upload?path=/up/pack.tgz", data=tarred.getvalue(), host=FILES_HOST, headers=token)
        status, _, part = request(user, "GET", "/archive?path=/up/pack.tgz", host=FILES_HOST)
        check("a tar.gz archive lists its entries and marks one that would leave the folder, and a link",
              status == 200 and ">tdir/t.txt<" in part and ">../tevil.txt<" in part and "Not unpacked" in part
              and "A link, which is not unpacked" in part, f"{status} {alerts(part)}")
        _, _, inner = request(user, "GET", "/archive/entry?path=/up/pack.tgz&entry=0", host=FILES_HOST)
        check("one file of a tar.gz archive downloads unpacked", inner == "tarred " * 1000, f"{len(inner)} characters")
        status, _, page = request(user, "POST", "/archive/extract", {"csrf": csrf_token, "path": "/up/pack.tgz"}, host=FILES_HOST)
        _, _, unpacked = request(user, "GET", "/download?path=/up/tdir/t.txt", host=FILES_HOST)
        status2, _, _ = request(user, "GET", "/size?path=/tevil.txt", host=FILES_HOST)
        check("a tar.gz archive unpacks beside itself, and an entry leaving the folder and a link are refused",
              status == 422 and "tevil.txt was not unpacked" in page and "to-passwd was not unpacked" in page
              and unpacked == "tarred " * 1000 and status2 == 422, f"{status} {status2} {alerts(page)}")
        status, _, page = request(user, "GET", "/search?path=/up&q=B.TXT", host=FILES_HOST)
        check("a search finds names in every folder below, whatever their case",
              status == 200 and 'href="./?path=/up/tree/a"' in page and 'href="./?path=/up/tree%20copy/a"' in page
              and "2 names found" in page, f"{status} {alerts(page)}")
        status, _, page = request(user, "GET", "/search?path=/up&q=%3Cb%3Ex%3C/b%3E", host=FILES_HOST)
        check("a search shows its query as text", status == 200 and escaped("<b>x</b>", page) and "<b>x</b>" not in page,
              f"{status}")
        request(user, "POST", "/move", [("csrf", csrf_token), ("folder", "/up"), ("path", "/up/part.bin"), ("to", "/up/deep/er")],
                host=FILES_HOST)
        _, _, page = request(user, "GET", "/?path=/up/deep/er", host=FILES_HOST)
        check("a file moves into another folder", 'data-path="/up/deep/er/part.bin"' in page, "")
        status, _, page = request(user, "POST", "/move",
                                  [("csrf", csrf_token), ("folder", "/up"), ("path", "/up/deep"), ("to", "/up/deep/er")],
                                  host=FILES_HOST)
        check("a folder cannot move into itself", status == 422 and "cannot move into itself" in page, f"{status}")
        request(user, "POST", "/delete", [("csrf", csrf_token), ("folder", "/up"), ("path", "/up/renamed.txt"), ("path", "/up/made"),
                                          ("path", "/up/tree"), ("path", "/up/tree copy"), ("path", "/up/deep"),
                                          ("path", "/up/inner"), ("path", "/up/pack.zip"), ("path", "/up/tdir"),
                                          ("path", "/up/pack.tgz")], host=FILES_HOST)
        _, _, page = request(user, "GET", "/?path=/up", host=FILES_HOST)
        check("files and folders are deleted, folders with everything in them",
              ">renamed.txt<" not in page and 'data-path="/up/made"' not in page and 'data-path="/up/tree' not in page
              and 'data-path="/up/deep"' not in page and ">hello.txt<" in page, "")
        status, _, text = request(user, "POST", "/share", {"path": "/up/hello.txt", "days": "7", "password": ""}, host=FILES_HOST,
                                  headers=token)
        share = json.loads(text).get("token", "") if status == 200 else ""
        check("a share link is made for a file", status == 200 and len(share) > 20, f"{status} {text[:80]!r}")
        guest = {"cookies": {}}
        _, _, page = request(guest, "GET", "/s", host=FILES_HOST)
        login_token = hidden(page, "login_token")
        status, _, shown = request(guest, "POST", "/s/info", {"login_token": login_token, "token": share}, host=FILES_HOST)
        check("a share link's page names its file", status == 200 and '"name":"hello.txt"' in shown, f"{status} {shown[:80]!r}")
        status, _, body = request(guest, "POST", "/s/get", {"login_token": login_token, "token": share, "password": ""},
                                  host=FILES_HOST)
        check("a share link downloads its file", status == 200 and body == "hello from sftp\n", f"{status} {body[:60]!r}")
        time.sleep(1)
        status, _, text = request(guest, "POST", "/s/get", {"login_token": login_token, "token": share, "password": ""},
                                  host=FILES_HOST)
        check("a share link works for one download", status == 422 and "does not work" in text, f"{status} {text[:80]!r}")
        _, _, listed = request(user, "GET", "/links", host=FILES_HOST)
        check("the maker's links page shows the link as used", "/up/hello.txt" in listed and ">Used<" in listed, "")
        _, _, part = request(user, "GET", "/details?path=/up/hello.txt", host=FILES_HOST)
        check("the details pane names a file's size and permissions",
              "<dt>Size</dt><dd>16 B</dd>" in part and "<dt>Permissions</dt>" in part, f"{part[:160]!r}")
        request(user, "PUT", "/upload?path=/up/history.txt", data=b"kept", host=FILES_HOST, headers=token)
        # The collector reads the event log once a second.
        for _ in range(20):
            _, _, part = request(user, "GET", "/details?path=/up/history.txt", host=FILES_HOST)
            if "Added by" in part:
                break
            time.sleep(0.5)
        check("the details pane says who added a file, from where and how, and lists its activity",
              f"<dt>Added by</dt><dd>{name} from" in part and "over the file browser" in part and ">Uploaded" in part
              and "127.0.0.1" not in part, f"{part[-300:]!r}")
        request(user, "POST", "/delete", [("csrf", csrf_token), ("folder", "/up"), ("path", "/up/history.txt")],
                host=FILES_HOST)
    if access == "readonly":
        status, _, _ = request(user, "POST", "/logout", {"csrf": hidden(page, "csrf")}, host=FILES_HOST)
        status2, _, _ = request(user, "GET", "/", host=FILES_HOST)
        check("signing out ends the file browser session", status == 303 and status2 == 303, f"{status} {status2}")
        _, _, page = request(st, "GET", f"/accounts/{name}")
        check("the account page shows the sign-in as set up", ">Set up<" in page and "<dd>Never</dd>" not in page, "")
        return
    _, _, page = request(st, "GET", f"/accounts/{name}")
    request(st, "POST", f"/accounts/{name}/files-reset", {"csrf": csrf(page)})
    status, _, text = request(user, "GET", "/?path=/up", host=FILES_HOST, headers={"Sec-Fetch-Mode": "cors"})
    check("an admin's reset of the sign-in ends the session in progress", status == 401 and "session has ended" in text,
          f"{status} {text[:80]!r}")
    status, headers, _ = request(user, "GET", "/", host=FILES_HOST)
    check("a page opened after the session ended goes to the sign-in page",
          status == 303 and headers.get("Location") == "/login", f"{status} {headers.get('Location')}")
    _, _, page = request(st, "GET", f"/accounts/{name}")
    check("the account page shows the reset sign-in as not set up", "Not set up" in page, "")


def step_grant_manage(manager, target):
    st = load("admin")
    _, _, page = request(st, "GET", f"/accounts/{manager}")
    form = [("csrf", csrf(page)), ("password_mode", "keep"), ("uid", hidden(page, "uid")), ("gid", hidden(page, "gid")),
            ("dirs", "up"), ("preset", "readonly"), ("web", "on"), ("manage", target)]
    status, _, made = request(st, "POST", f"/accounts/{manager}", form)
    check(f"an admin lets {manager} manage {target}", status == 303, f"{status} {alerts(made)}")


def files_sign_in(name, headers=None):
    """Signs `name` in to the file browser with the password and second
    factor step_files set, sending `headers`; returns the session, the
    status and the page. A code works once and only for a step after the
    last one used, within a step of now, so this waits, under a minute,
    until such a step is in reach, and keeps the step it used."""
    me = load(f"files-{name}")
    while int(time.time()) // 30 + 1 <= me["step"]:
        time.sleep(1)
    me["step"] = max(me["step"] + 1, int(time.time()) // 30)
    save(f"files-{name}", me)
    user = {"cookies": {}}
    _, _, page = request(user, "GET", "/login", headers=headers, host=FILES_HOST)
    form = {"login_token": hidden(page, "login_token"), "name": name, "password": me["password"],
            "code": totp(me["secret"], me["step"] * 30)}
    status, _, page = request(user, "POST", "/login", form, headers=headers, host=FILES_HOST)
    return user, status, page


def step_manager(manager, target):
    user, status, _ = files_sign_in(manager)
    _, _, page = request(user, "GET", "/", host=FILES_HOST)
    check(f"{manager} sees {target} among the accounts it manages", status == 303 and f'href="/m/{target}/"' in page, f"{status}")
    status, _, page = request(user, "GET", f"/m/{target}/?path=/up", host=FILES_HOST)
    check(f"{manager} opens the files of {target}", status == 200 and ">hello.txt<" in page and "You are in the files of" in page,
          f"{status} {alerts(page)}")
    token = {"X-CSRF-Token": hidden(page, "csrf")}
    status, _, text = request(user, "PUT", f"/m/{target}/upload?path=/up/from-manager.txt", data=b"managed", host=FILES_HOST,
                              headers=token)
    _, _, body = request(user, "GET", f"/m/{target}/download?path=/up/from-manager.txt", host=FILES_HOST)
    check(f"{manager} works in the files of {target} with what {target} may do", status == 200 and body == "managed",
          f"{status} {text[:80]!r} {body[:40]!r}")
    _, _, own = request(user, "GET", "/?path=/up", host=FILES_HOST)
    check(f"what {manager} does there stays in the files of {target}", ">from-manager.txt<" not in own, "")
    status, _, text = request(user, "GET", "/m/root/?path=/", host=FILES_HOST)
    check("an account the manager does not manage is refused", status == 403 and "may not open the files of root" in text, f"{status}")
    request(user, "POST", f"/m/{target}/delete", {"csrf": hidden(page, "csrf"), "folder": "/up", "path": "/up/from-manager.txt"},
            host=FILES_HOST)
    st = load("admin")
    _, _, form_page = request(st, "GET", "/groups/new")
    status, _, made = request(st, "POST", "/groups/new", [("csrf", csrf(form_page)), ("name", "sharers"), ("gid", ""), ("preset", ""),
                                                          ("sharedays", "2"), ("sharepassword", "on"), ("members", target)])
    check("an admin gives a group share link limits", status == 303, f"{status} {alerts(made)}")
    _, _, page = request(user, "GET", f"/m/{target}/?path=/up", host=FILES_HOST)
    check(f"the share dialog for the files of {target} offers what its group allows",
          '<option value="1">1 day</option><option value="2" selected>2 days</option></select>' in page
          and 'required placeholder="Required here"' in page, f"{alerts(page)}")
    token = {"X-CSRF-Token": hidden(page, "csrf")}
    status, _, longer = request(user, "POST", f"/m/{target}/share", {"path": "/up/hello.txt", "days": "7", "password": ""},
                                host=FILES_HOST, headers=token)
    status2, _, bare = request(user, "POST", f"/m/{target}/share", {"path": "/up/hello.txt", "days": "2", "password": ""},
                               host=FILES_HOST, headers=token)
    status3, _, made = request(user, "POST", f"/m/{target}/share", {"path": "/up/hello.txt", "days": "2", "password": "share-pw-1"},
                               host=FILES_HOST, headers=token)
    check("a share link longer than the group allows, or without the password it requires, is refused",
          status == 422 and "1 to 2 days" in longer and status2 == 422 and "needs a password" in bare and status3 == 200,
          f"{status} {status2} {status3} {longer[:60]!r} {bare[:60]!r} {made[:60]!r}")
    _, _, form_page = request(st, "GET", "/groups/sharers")
    status, _, made = request(st, "POST", "/groups/sharers", [("csrf", csrf(form_page)), ("gid", ""), ("preset", ""),
                                                              ("noshare", "on"), ("members", target)])
    _, _, page = request(user, "GET", f"/m/{target}/?path=/up", host=FILES_HOST)
    status2, _, text = request(user, "POST", f"/m/{target}/share", {"path": "/up/hello.txt", "days": "1", "password": "share-pw-1"},
                               host=FILES_HOST, headers={"X-CSRF-Token": hidden(page, "csrf")})
    check("a group's noshare takes Share off the menu and refuses links to its members' files",
          status == 303 and 'data-fm-act="share"' not in page and status2 == 422 and "are off for these files" in text,
          f"{status} {status2} {text[:80]!r} {alerts(made)}")
    _, _, form_page = request(st, "GET", "/groups/sharers")
    request(st, "POST", "/groups/sharers/delete", {"csrf": csrf(form_page)})
    _, _, form_page = request(st, "GET", f"/accounts/{manager}")
    own = [("csrf", csrf(form_page)), ("password_mode", "keep"), ("uid", hidden(form_page, "uid")), ("gid", hidden(form_page, "gid")),
           ("dirs", "up"), ("preset", "readonly"), ("web", "on"), ("manage", target)]
    status, _, made = request(st, "POST", f"/accounts/{manager}", own + [("noshare", "on")])
    _, _, page = request(user, "GET", f"/m/{target}/?path=/up", host=FILES_HOST)
    status2, _, text = request(user, "POST", f"/m/{target}/share", {"path": "/up/hello.txt", "days": "1", "password": "share-pw-1"},
                               host=FILES_HOST, headers={"X-CSRF-Token": hidden(page, "csrf")})
    check(f"noshare on the line of {manager} stops its links to the files it manages",
          status == 303 and 'data-fm-act="share"' not in page and status2 == 422 and "are off for these files" in text,
          f"{status} {status2} {text[:80]!r} {alerts(made)}")
    _, _, form_page = request(st, "GET", f"/accounts/{manager}")
    own[0] = ("csrf", csrf(form_page))
    request(st, "POST", f"/accounts/{manager}", own)


def step_countries():
    st = load("admin")
    status, _, page = request(st, "GET", "/bans")
    check("the Countries card starts off, with the default list",
          status == 200 and ">Off</span>" in page and 'name="country" value="CN" checked' in page, f"{status}")
    form = [("csrf", csrf(page)), ("list", "1"), ("rule", "block"), ("country", "CN"), ("country", "ru"), ("country", "")]
    status, _, _ = request(st, "POST", "/bans/countries", form)
    _, _, text = request(st, "GET", "/bans")
    check("the Countries card saves and applies a block list",
          status == 303 and "Country rules saved and applied" in text and "Blocking 2 countries" in text, f"{status}")
    check("the saved list holds each chosen country once, by name",
          'name="country" value="RU" checked' in text and '<span class="chip-text">China</span>' in text
          and 'value="IN" checked' not in text, "")
    # Through the trusted proxy, from TEST-NET-2, an address in no country.
    away, headers = {"cookies": {}}, {"X-Forwarded-For": "198.51.100.7"}
    status, _, _ = request(away, "GET", "/login", headers=headers)
    check("block lets an address in no country reach the web UI", status == 200, f"{status}")
    far = {"cookies": {}}
    status, _, _ = request(far, "GET", "/login", headers=headers, host=FILES_HOST)
    check("block lets an address in no country reach the file browser", status == 200, f"{status}")
    request(st, "POST", "/bans/countries", [("csrf", csrf(text)), ("list", "1"), ("rule", "allow")])
    _, _, text = request(st, "GET", "/bans")
    check("allowing only listed countries with none listed is refused",
          "needs at least one country" in text and "Blocking 2 countries" in text, "")
    request(st, "POST", "/bans/countries", [("csrf", csrf(text)), ("list", "1"), ("rule", "allow"), ("country", "US")])
    # The web UI reads the rules in force again every two seconds.
    for _ in range(10):
        status, _, refused = request(away, "GET", "/login", headers=headers)
        if status == 403:
            break
        time.sleep(0.5)
    check("allow keeps an address in no country out of the web UI",
          status == 403 and "does not accept connections from your location" in refused, f"{status}")
    # The file browser reads the rules in force on its own clock.
    for _ in range(10):
        status, _, refused = request(far, "GET", "/login", headers=headers, host=FILES_HOST)
        if status == 403:
            break
        time.sleep(0.5)
    check("allow keeps an address in no country out of the file browser",
          status == 403 and "does not accept connections from your location" in refused, f"{status}")
    status, _, text = request(st, "GET", "/bans")
    check("a private address still reaches the web UI under allow", status == 200 and "Allowing 1 country" in text, f"{status}")
    request(st, "POST", "/bans/countries", [("csrf", csrf(text)), ("list", "1"), ("rule", "off"), ("country", "CN")])
    _, _, text = request(st, "GET", "/bans")
    check("turning the rule off is saved and applied", ">Off</span>" in text and 'value="CN" checked' in text, "")


def step_invite(reader_password):
    st = load("admin")
    _, _, page = request(st, "GET", "/admins")
    request(st, "POST", "/admins/invite", {"csrf": csrf(page), "name": "reader", "role": "read-only"})
    _, _, text = request(st, "GET", "/admins")
    m = re.search(r"/invite\?token=([A-Za-z0-9_-]+)", text)
    if not check("an invite shows its link once", m is not None, ""):
        return
    token = m.group(1)
    rd = {"cookies": {}}
    _, _, page = request(rd, "GET", f"/invite?token={token}")
    form = {"login_token": hidden(page, "login_token"), "token": token, "name": "reader",
            "password": reader_password, "confirm": reader_password}
    status, _, _ = request(rd, "POST", "/invite", form)
    check("the invited admin sets a password and is signed in", status == 303 and "__Host-sftp_session" in rd["cookies"], f"{status}")
    status, _, page = request(rd, "GET", "/accounts")
    check("a read-only admin sees the accounts", status == 200 and "Accounts" in page, f"{status}")
    status, _, text = request(rd, "POST", "/accounts/new", {"csrf": csrf(page), "name": "nope", "password_mode": "clear", "preset": "full"})
    check("a read-only admin cannot change anything", status == 403 and "read-only" in text, f"{status}")
    status, _, _ = request(rd, "GET", f"/invite?token={token}")
    check("an invite link works once", status == 404, f"{status}")


def step_totp(name, password):
    st = load("admin")
    _, _, page = request(st, "GET", "/me")
    request(st, "POST", "/me/totp/start", {"csrf": csrf(page)})
    _, _, page = request(st, "GET", "/me")
    m = re.search(r"<code>([A-Z2-7]{16,})</code>", page)
    if not check("two-factor setup shows a key and a QR code", m is not None and "<svg" in page, ""):
        return
    secret = m.group(1)
    request(st, "POST", "/me/totp/confirm", {"csrf": csrf(page), "code": totp(secret, time.time())})
    _, _, page = request(st, "GET", "/me")
    check("a correct code turns two-factor sign-in on", "Two-factor sign-in is on" in page, "")
    fresh = {"cookies": {}}
    status, _, _ = login(fresh, name, password)
    check("with two-factor on, a password alone is refused", status == 401, f"{status}")
    status, _, _ = login(fresh, name, password, totp(secret, time.time() + 30))
    check("password and code sign in", status == 303, f"{status}")
    status, _, _ = login({"cookies": {}}, name, password, totp(secret, time.time() + 30))
    check("a code is accepted once", status == 401, f"{status}")


def step_audit():
    st = load("admin")
    _, _, text = request(st, "GET", "/audit")
    check("the audit log records the account change", "account created" in text and "settings changed" in text, "")
    _, _, text = request(st, "GET", "/logs?q=sftp-webui")
    check("the log page searches the auth log", "login of admin" in text, "")


def step_delete_account(name):
    st = load("admin")
    _, _, page = request(st, "GET", f"/accounts/{name}")
    status, _, _ = request(st, "POST", f"/accounts/{name}/delete", {"csrf": csrf(page), "delete_keys": "on"})
    check(f"the UI deletes {name}", status == 303, f"{status}")


def step_logout():
    st = load("admin")
    _, _, page = request(st, "GET", "/")
    request(st, "POST", "/logout", {"csrf": csrf(page)})
    status, _, _ = request(st, "GET", "/")
    check("after logout the session is gone", status == 303, f"{status}")


def step_lockout(name):
    st = {"cookies": {}}
    statuses = [login(st, name, "wrong password %d" % i)[0] for i in range(6)]
    check("five failed logins lock the address out", statuses[:5] == [401] * 5 and statuses[5] == 429, str(statuses))


def held_rows(page, account, address):
    """The Bans page's rows for held sign-ins of `account` from `address`."""
    return [row for row in page.split("</tr>")
            if f'<code class="name">{account}</code>' in row and f"<code>{address}</code>" in row]


def locked_rows(page, account):
    """The Bans page's rows for `account` locked down."""
    return [row for row in page.split("</tr>")
            if 'data-label="Last failed sign-in"' in row and f'<code class="name">{account}</code>' in row]


def step_held(account, address):
    """The held sign-in of `account` from `address`: listed once however
    often it was tried, counted on the Status page, and approved."""
    st = load("admin")
    status, _, text = request(st, "GET", "/bans")
    rows = held_rows(text, account, address)
    check(f"the Bans page lists the held sign-in of {account} from {address} once",
          status == 200 and len(rows) == 1, f"{status}, {len(rows)} rows {alerts(text)}")
    status, _, page = request(st, "GET", "/")
    check("the Status page says a sign-in is waiting for approval", status == 200 and "waiting for approval" in page, f"{status}")
    hold = re.search(r'name="id" value="(\d+)"', rows[0]) if rows else None
    if hold is None:
        return
    status, _, _ = request(st, "POST", "/bans/holds", {"csrf": csrf(text), "id": hold.group(1), "action": "approve"})
    _, _, text = request(st, "GET", "/bans")
    check("approving the held sign-in clears it from the Bans page",
          status == 303 and "Sign-in approved" in text and not held_rows(text, account, address), f"{status} {alerts(text)}")


def step_files_held(name, address):
    """A file browser sign-in through the proxy from `address`, a place the
    account's profile lacks: held with the right password and code, while a
    wrong password from there still fails as one; once approved, it goes
    through."""
    via = {"X-Forwarded-For": address}
    _, status, page = files_sign_in(name, via)
    check("a file browser sign-in from a new place is held, with the right password and code",
          status == 401 and "held until an admin approves it" in page, f"{status}")
    wrong = {"cookies": {}}
    _, _, page = request(wrong, "GET", "/login", headers=via, host=FILES_HOST)
    form = {"login_token": hidden(page, "login_token"), "name": name, "password": "not-the-password", "code": ""}
    status, _, page = request(wrong, "POST", "/login", form, headers=via, host=FILES_HOST)
    check("a wrong file browser password from there is refused as one", status == 401 and "Wrong name or password" in page,
          f"{status}")
    step_held(name, address)
    _, status, _ = files_sign_in(name, via)
    check("once approved, the file browser sign-in from there goes through", status == 303, f"{status}")


def step_locked(account):
    """A password spray against `account` shows as a lockdown on the Bans
    page and the Status page."""
    st = load("admin")
    # The collector reads the failures within a second or two.
    for _ in range(20):
        status, _, text = request(st, "GET", "/bans")
        if locked_rows(text, account):
            break
        time.sleep(0.5)
    check(f"a password spray against {account} locks it down", status == 200 and len(locked_rows(text, account)) == 1,
          f"{status} {alerts(text)}")
    status, _, page = request(st, "GET", "/")
    check("the Status page says an account is locked down", status == 200 and "locked down" in page, f"{status}")


def step_lift(account):
    st = load("admin")
    _, _, text = request(st, "GET", "/bans")
    status, _, _ = request(st, "POST", "/bans/lockdowns/lift", {"csrf": csrf(text), "account": account})
    _, _, text = request(st, "GET", "/bans")
    check(f"lifting the lockdown of {account} clears it from the Bans page",
          status == 303 and "Lockdown lifted" in text and not locked_rows(text, account), f"{status} {alerts(text)}")


STEPS = {
    "fresh": step_fresh,
    "setup": step_setup,
    "protections": step_protections,
    "create-account": step_create_account,
    "activity": step_activity,
    "sessions": step_sessions,
    "settings": step_settings,
    "bans": step_bans,
    "countries": step_countries,
    "files": step_files,
    "grant-manage": step_grant_manage,
    "manager": step_manager,
    "invite": step_invite,
    "totp": step_totp,
    "audit": step_audit,
    "delete-account": step_delete_account,
    "logout": step_logout,
    "lockout": step_lockout,
    "held": step_held,
    "files-held": step_files_held,
    "locked": step_locked,
    "lift": step_lift,
}

STEPS[STEP](*ARGS)
