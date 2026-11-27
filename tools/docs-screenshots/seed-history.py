"""Adds a week of plausible history before the demo server's first event:
the demo accounts' sign-ins and transfers, mostly in working hours, and
password guessers' failed sign-ins and bans around the clock. Addresses are
from the documentation ranges and a private network. Runs inside the
container. Usage: python3 seed-history.py"""

import random
import sqlite3
import time

DB = "/config/webui/history.sqlite3"
PEOPLE = {
    "alice": ("203.0.113.24", "password", "/upload"),
    "bob": ("198.51.100.42", "publickey", "/inbox"),
    "carol": ("203.0.113.61", "password", "/reports"),
    "erin": ("10.0.4.17", "password", "/upload"),
}
FILES = ["report.pdf", "invoices.zip", "photos.tar.gz", "notes.txt", "budget.xlsx", "contract.pdf", "backup.tar.gz", "slides.pdf"]
NAMES = ["root", "admin", "test", "ubuntu", "oracle", "user", "git", "postgres", "deploy", "pi", "guest", "ftp"]


def main():
    rng = random.Random(2290)
    conn = sqlite3.connect(DB, timeout=60)
    first = conn.execute("SELECT min(time) FROM events").fetchone()[0]
    end = first - 60
    start = end - 7 * 86400
    events, bans = [], []
    for hour_start in range(start - start % 3600, end - 3600, 3600):
        moment = time.gmtime(hour_start)
        busy = 13 <= moment.tm_hour <= 23 and moment.tm_wday < 5
        for account, (address, method, folder) in PEOPLE.items():
            if rng.random() >= (0.55 if busy else 0.05):
                continue
            t = hour_start + rng.randrange(3000)
            events.append((t, "ssh", "login_ok", account, address, "", method, 0, ""))
            for _ in range(rng.randrange(1, 6)):
                t += rng.randrange(5, 90)
                kind = "download" if account == "bob" or rng.random() < 0.4 else "upload"
                size = int(rng.lognormvariate(14, 1.3))
                events.append((t, "ssh", kind, account, address, f"{folder}/{rng.choice(FILES)}", "", size, ""))
        for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
            t = hour_start + rng.randrange(3000)
            attacker = rng.choice(["198.51.100.", "203.0.113.", "192.0.2."]) + str(rng.randrange(100, 250))
            tries = rng.sample(NAMES, 5)
            for name in tries:
                t += rng.randrange(1, 4)
                events.append((t, "ssh", "login_failed", name, attacker, "", "password", 0, ""))
            bans.append(("sshd", attacker, t, 3600, 1, 5, tries[0]))
    with conn:
        conn.executemany(
            "INSERT INTO events (time, door, kind, account, address, path, other, bytes, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            events,
        )
        conn.executemany("INSERT OR IGNORE INTO bans VALUES (?, ?, ?, ?, ?, ?, ?)", bans)
    print(f"seeded {len(events)} events and {len(bans)} bans")


if __name__ == "__main__":
    main()
