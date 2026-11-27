"""Takes the documentation's screenshots of the demo server up.sh starts: the
admin web UI on port 8443 and the file browser on port 8444 of ADDRESS,
which the browser knows as sftp.example.com, into OUT. Each browser sends a
documentation address in X-Forwarded-For, so pages show those addresses.
Saves the web secrets it enrolls in OUT/secrets.json, so a later run signs
in instead.

Usage: python shoot.py ADDRESS SETUP_TOKEN OUT [files | crops]
With files it takes only the file browser's screenshots; with crops, only
the section crops and the dashboard."""

import base64
import hashlib
import hmac
import json
import re
import struct
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

HOST = "sftp.example.com"
ADMIN = ("admin", "Demo-Admin-Pass-2290")
WEB_PASSWORD = {"alice": "Alice-Web-Pass-7781", "carol": "Carol-Web-Pass-5530"}
VIEW = {"width": 1280, "height": 800}
ADDRESSES = {"admin": "198.51.100.7", "alice": "203.0.113.24", "carol": "203.0.113.61", "visitor": "198.51.100.150"}
PAGES = [
    ("/", "status"), ("/accounts", "accounts"), ("/accounts/new", "account-new"),
    ("/accounts/alice", "account-alice"), ("/accounts/bob", "account-bob"), ("/accounts/carol", "account-carol"),
    ("/accounts/dave", "account-dave"), ("/accounts/erin", "account-erin"), ("/groups", "groups"),
    ("/groups/staff", "group-staff"), ("/groups/partners", "group-partners"), ("/bans", "bans"),
    ("/settings", "settings"), ("/activity", "activity"), ("/logs", "logs"), ("/audit", "audit"),
    ("/admins", "admins"), ("/me", "me"),
]
CROPS = [
    ("/accounts/alice", "Account", "account-details"),
    ("/accounts/alice", "Password", "account-password"),
    ("/accounts/alice", "Permissions", "account-permissions"),
    ("/accounts/alice", "Access", "account-access"),
    ("/accounts/alice", "File browser", "account-files"),
    ("/accounts/erin", "Access", "account-access-rsync"),
    ("/accounts/bob", "Public keys", "account-keys"),
    ("/accounts/bob", "Open sessions", "account-sessions"),
    ("/bans", "Countries", "bans-countries"),
    ("/bans", "Rules", "bans-rules"),
    ("/settings", "SFTP server", "settings-server"),
    ("/settings", "Locations", "settings-locations"),
    ("/me", "Two-factor sign-in", "me-two-factor"),
    ("/admins", "Invite an admin", "admins-invite"),
]
# Taken after seed-signins.py, with the "signins" argument.
SIGNIN_CROPS = [
    ("/bans", "Held sign-ins", "bans-held"),
    ("/bans", "Locked accounts", "bans-locked"),
]
# The nearest section or card around a heading.
NEAREST = (
    "xpath=ancestor::*[contains(concat(' ', normalize-space(@class), ' '), ' section ')"
    " or contains(concat(' ', normalize-space(@class), ' '), ' card ')][1]"
)


def totp(secret):
    clean = secret.replace(" ", "").upper()
    key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000)


def settle(page):
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(500)


def both(page, take):
    """Calls take("") in the light color scheme, then take("-dark") in the
    dark one. The UI follows prefers-color-scheme when no theme is saved, so
    the page repaints in place and keeps its state."""
    take("")
    page.emulate_media(color_scheme="dark")
    page.wait_for_timeout(400)
    take("-dark")
    page.emulate_media(color_scheme="light")
    page.wait_for_timeout(400)


def shot(page, path, full=True):
    settle(page)

    def take(suffix):
        target = path.with_name(path.stem + suffix + path.suffix)
        page.screenshot(path=str(target), full_page=full)
        print("shot", target.name)

    both(page, take)


def context(browser, who):
    return browser.new_context(
        viewport=VIEW, color_scheme="light", ignore_https_errors=True, locale="en-US",
        extra_http_headers={"X-Forwarded-For": ADDRESSES[who]},
    )


def admin_pages(browser, admin, token, out):
    page = context(browser, "admin").new_page()
    page.goto(f"{admin}/login")
    shot(page, out / "login.png", full=False)
    page.goto(f"{admin}/setup?token={token}")
    if page.locator("input[name=confirm]").count():
        page.fill("input[name=name]", ADMIN[0])
        page.fill("input[name=password]", ADMIN[1])
        page.fill("input[name=confirm]", ADMIN[1])
        shot(page, out / "setup.png", full=False)
        page.click("button[type=submit]")
    else:
        page.goto(f"{admin}/login")
        page.fill("input[name=name]", ADMIN[0])
        page.fill("input[name=password]", ADMIN[1])
        page.click("button[type=submit]")
    settle(page)
    return page


def crops(page, admin, out, which=CROPS):
    for path, title, name in which:
        page.goto(admin + path)
        settle(page)
        page.evaluate("document.querySelectorAll('.form-bar').forEach(e => { e.style.display = 'none'; })")
        heading = page.locator("h2").filter(has_text=re.compile(rf"^\s*{re.escape(title)}\s*$")).first
        section = heading.locator(NEAREST)

        def take(suffix, section=section, name=name):
            section.screenshot(path=str(out / f"{name}{suffix}.png"))
            print("shot", f"{name}{suffix}.png")

        both(page, take)


def dashboard(browser, admin_page, admin, out):
    """The README's Status page at twice the resolution, light and dark; the
    README shows the one that matches the reader's theme."""
    state = admin_page.context.storage_state()
    for scheme, name in [("light", "dashboard.png"), ("dark", "dashboard-dark.png")]:
        page = browser.new_context(
            viewport=VIEW, device_scale_factor=2, color_scheme=scheme, ignore_https_errors=True, locale="en-US",
            extra_http_headers={"X-Forwarded-For": ADDRESSES["admin"]},
            storage_state=state,
        ).new_page()
        page.goto(admin + "/")
        shot(page, out / name, full=False)


def make_link(page, admin, name, out):
    page.goto(f"{admin}/accounts/{name}")
    page.get_by_role("button", name="Make a sign-in link").click()
    shot(page, out / f"account-{name}-link.png", full=False)
    found = re.search(r"/invite([?#])token=([A-Za-z0-9_\-]+)", page.content())
    return f"{found.group(1)}token={found.group(2)}"


def files_pages(browser, files, name, link, secrets, out):
    page = context(browser, name).new_page()
    if name not in secrets:
        page.goto(f"{files}/invite{link}")
        shot(page, out / f"files-invite-{name}.png", full=False)
        secrets[name] = page.input_value("input[name=secret]")
        page.fill("input[name=password]", WEB_PASSWORD[name])
        page.fill("input[name=confirm]", WEB_PASSWORD[name])
        page.fill("input[name=code]", totp(secrets[name]))
        page.click("button[type=submit]")
        shot(page, out / f"files-ready-{name}.png", full=False)
        # Each code works once, so the sign-in waits for the next one.
        time.sleep(31 - time.time() % 30)
    page.goto(f"{files}/login")
    page.fill("input[name=name]", name)
    page.fill("input[name=password]", WEB_PASSWORD[name])
    page.fill("input[name=code]", totp(secrets[name]))
    page.click("button[type=submit]")
    shot(page, out / f"files-home-{name}.png", full=False)
    return page


def open_folder(page, files, path):
    page.goto(f"{files}/?path={path}")
    settle(page)


def menu(page, path, action):
    page.click(f'tr[data-path="{path}"]', button="right")
    page.click(f"[data-fm-act={action}]:visible")


def alice_tour(page, files, out):
    open_folder(page, files, "/upload")
    page.dblclick('tr[data-path="/upload/site-photos.zip"]')
    shot(page, out / "files-archive.png", full=False)
    open_folder(page, files, "/upload")
    menu(page, "/upload/quarterly-report.pdf", "share")
    shot(page, out / "files-share.png", full=False)
    page.get_by_role("button", name="Make the link").click()
    shot(page, out / "files-share-made.png", full=False)
    link = page.get_attribute("[data-share-copy]", "data-copy")
    page.keyboard.press("Escape")
    open_folder(page, files, "/photos")
    menu(page, "/photos/harbor.png", "preview")
    shot(page, out / "files-preview.png", full=False)
    page.keyboard.press("Escape")
    page.click("[data-fmview=grid]")
    shot(page, out / "files-grid.png", full=False)
    page.click("[data-fmview=list]")
    page.goto(f"{files}/links")
    shot(page, out / "files-links.png", full=False)
    return link


def details_shot(page, files, out):
    open_folder(page, files, "/upload")
    page.set_viewport_size({"width": 1280, "height": 1150})
    with page.expect_response(lambda r: "/details?path=" in r.url):
        page.click('tr[data-path="/upload/quarterly-report.pdf"]')
    shot(page, out / "files-details.png", full=False)
    page.set_viewport_size(VIEW)


def carol_tour(page, files, out):
    page.goto(f"{files}/m/bob/?path=/inbox")
    settle(page)
    page.click('tr[data-path="/inbox/contract-draft.pdf"]')
    shot(page, out / "files-manage.png", full=False)


def main():
    address, token, out = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    only_files = sys.argv[4:] == ["files"]
    out.mkdir(parents=True, exist_ok=True)
    admin, files = f"https://{HOST}:8443", f"https://{HOST}:8444"
    store = out / "secrets.json"
    secrets = json.loads(store.read_text()) if store.exists() else {}
    with sync_playwright() as p:
        browser = p.chromium.launch(
            channel="msedge", headless=True, args=[f"--host-resolver-rules=MAP {HOST} {address}"]
        )
        if sys.argv[4:] == ["crops"]:
            admin_page = admin_pages(browser, admin, token, out)
            crops(admin_page, admin, out)
            dashboard(browser, admin_page, admin, out)
            browser.close()
            return
        if sys.argv[4:] == ["signins"]:
            crops(admin_pages(browser, admin, token, out), admin, out, SIGNIN_CROPS)
            browser.close()
            return
        page = context(browser, "visitor").new_page()
        page.goto(f"{files}/login")
        shot(page, out / "files-login.png", full=False)
        admin_page = None if only_files else admin_pages(browser, admin, token, out)
        tours = {"alice": alice_tour, "carol": carol_tour}
        share = ""
        pages = {}
        for name in WEB_PASSWORD:
            link = "" if name in secrets else make_link(admin_page, admin, name, out)
            pages[name] = files_pages(browser, files, name, link, secrets, out)
            store.write_text(json.dumps(secrets))
            share = tours[name](pages[name], files, out) or share
        visitor = context(browser, "visitor").new_page()
        visitor.goto(share)
        shot(visitor, out / "share-page.png", full=False)
        with visitor.expect_download() as download:
            visitor.get_by_role("button", name="Download").click()
        print("downloaded", download.value.path())
        details_shot(pages["alice"], files, out)
        if admin_page is not None:
            for path, name in PAGES:
                admin_page.goto(admin + path)
                shot(admin_page, out / f"{name}.png", full=False)
            crops(admin_page, admin, out)
            dashboard(browser, admin_page, admin, out)
        browser.close()


if __name__ == "__main__":
    main()
