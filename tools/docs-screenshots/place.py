"""Copies the screenshots the documentation uses from OUT into the repository
at REPO: each /screenshots/NAME.png a page under wiki/content names goes to
wiki/static/screenshots with its dark twin NAME-dark.png, which the wiki
shows in dark mode, and the light and dark dashboards go to .github for the
README. It reports screenshots no page uses, and fails when OUT lacks one
a page names. Usage: python place.py OUT REPO"""

import re
import shutil
import sys
from pathlib import Path

DASHBOARDS = ["dashboard.png", "dashboard-dark.png"]


def main():
    out, repo = Path(sys.argv[1]), Path(sys.argv[2])
    names = set()
    for page in (repo / "wiki" / "content").rglob("*.md"):
        for name in re.findall(r"/screenshots/([a-z0-9-]+)\.png", page.read_text(encoding="utf-8")):
            names.update({f"{name}.png", f"{name}-dark.png"})
    missing = sorted(n for n in names | set(DASHBOARDS) if not (out / n).is_file())
    if missing:
        sys.exit(f"{out} has no " + ", ".join(missing))
    target = repo / "wiki" / "static" / "screenshots"
    target.mkdir(parents=True, exist_ok=True)
    for name in sorted(names):
        shutil.copyfile(out / name, target / name)
    for name in DASHBOARDS:
        shutil.copyfile(out / name, repo / ".github" / name)
    print(f"copied {len(names)} screenshots, light and dark, and the light and dark dashboards")
    for path in sorted(target.glob("*.png")):
        if path.name not in names:
            print(f"no page uses {path}")


if __name__ == "__main__":
    main()
