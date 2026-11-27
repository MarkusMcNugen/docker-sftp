"""Gives the demo server two held sign-ins and a password spray against
carol, for the Bans page's Held sign-ins and Locked accounts cards. Runs
inside the container once the other screenshots are taken, since the Status
page then warns of both. Addresses are from the documentation ranges.
Usage: python3 seed-signins.py"""

import sqlite3
import time

DB = "/config/webui/history.sqlite3"


def main():
    now = int(time.time())
    conn = sqlite3.connect(DB, timeout=60)
    holds = [
        (now - 240, "alice", "192.0.2.77", "BR", "New place: the account has not signed in from here"),
        (now - 1500, "bob", "203.0.113.140", "JP", "Impossible travel: 9840 km/h from its last sign-in in DE"),
    ]
    spray = [(52, "198.51.100.171"), (47, "203.0.113.208"), (41, "192.0.2.233"), (12, "198.51.100.86")]
    with conn:
        conn.executemany("INSERT INTO holds (time, account, address, place, reason) VALUES (?, ?, ?, ?, ?)", holds)
        conn.executemany(
            "INSERT INTO events (time, door, kind, account, address, path, other, bytes, actor) "
            "VALUES (?, 'ssh', 'login_failed', 'carol', ?, '', 'password', 0, '')",
            [(now - minutes * 60, address) for minutes, address in spray],
        )
    print(f"seeded {len(holds)} held sign-ins and {len(spray)} failed sign-ins against carol")


if __name__ == "__main__":
    main()
