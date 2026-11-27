# Docs screenshots

These scripts make the screenshots in `wiki/static/screenshots` and the README's light and dark dashboards in `.github` from a demo server, so they can be taken again for each release. The demo server holds made-up accounts and a week of seeded history, the browser calls it `sftp.example.com`, and every address it shows comes from the ranges set aside for documentation, so nothing real appears.

## What it needs

- A Linux machine with rootless Podman for the demo server, and the image to show, such as one built from this repository.
- Python 3 with Playwright and Pillow (`pip install playwright pillow`) and Microsoft Edge on the machine that takes the screenshots. Playwright drives the installed Edge, so it downloads no browser.
- That machine reaching the server's ports 2222, 8443 and 8444.

## Take them

1. On the server, start the demo server. It prints the first admin's setup token:

   ```bash
   bash tools/docs-screenshots/up.sh localhost/sftp:dev
   ```

2. On the machine with the browser, take the screenshots, giving the server's address and the token:

   ```bash
   python tools/docs-screenshots/shoot.py 192.0.2.10 <setup token> shots
   ```

3. On the server, give the demo a held sign-in and a password spray, then take the Bans page's two sign-in cards. They come last because the Status page warns of both:

   ```bash
   podman cp tools/docs-screenshots/seed-signins.py sftp-shots:/tmp/seed-signins.py
   podman exec sftp-shots python3 /tmp/seed-signins.py
   python tools/docs-screenshots/shoot.py 192.0.2.10 <setup token> shots signins
   ```

4. Look them over, four to a sheet: `python tools/docs-screenshots/sheet.py sheet.png shots/status.png shots/accounts.png ...`

5. Put the ones the docs use in place, and remove the demo server:

   ```bash
   python tools/docs-screenshots/place.py shots .
   bash tools/docs-screenshots/down.sh
   ```

A second run of `shoot.py` against the same server signs in instead of setting up. `crops` as a fourth argument retakes only the section crops and the dashboard; `files`, only the file browser; `signins`, only the two sign-in cards.

## The files

| File | What it is |
|---|---|
| `users.conf`, `groups.conf`, `settings.conf` | the demo accounts, groups and settings, with transfer logging on |
| `make-files.py` | the files the accounts upload: PDFs, pictures, notes, a zip and a tar.gz |
| `activity.sh`, `attack.sh` | uploads and downloads from a client container, and password guessers that fail2ban bans |
| `seed-history.py` | a week of sign-ins, transfers and bans before the live activity, so the charts have a shape |
| `seed-signins.py` | two held sign-ins and a password spray, for the Bans page's sign-in cards |
| `shoot.py` | the pages, the file browser tours, the section crops, and the dashboard at twice the resolution in light and dark |
| `place.py`, `sheet.py`, `down.sh` | putting the screenshots in place, contact sheets, and removing the demo server |

## Things that trip it up

- The web UI's Content Security Policy refuses injected styles, so the script hides the save bar through each element's own style.
- A two-factor code works once, so after enrolling an account the script waits for the next 30 s code before it signs in.
- File operations reach the history only with transfer logging on, which `settings.conf` turns on.
- Sessions must come from a client container rather than loopback: the history skips loopback sessions as the file browser's own.
