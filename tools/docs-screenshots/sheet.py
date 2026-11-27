"""Tiles up to four screenshots into one 1280-wide contact sheet, each at
half size from its top, with its file name above it.
Usage: python sheet.py OUT.png IMAGE..."""

import sys
from pathlib import Path

from PIL import Image, ImageDraw

CELL_W, CELL_H, LABEL = 640, 400, 18


def main():
    out, images = Path(sys.argv[1]), [Path(a) for a in sys.argv[2:]]
    rows = (len(images) + 1) // 2
    sheet = Image.new("RGB", (CELL_W * 2, (CELL_H + LABEL) * rows), "white")
    draw = ImageDraw.Draw(sheet)
    for i, path in enumerate(images):
        x, y = (i % 2) * CELL_W, (i // 2) * (CELL_H + LABEL)
        shot = Image.open(path).convert("RGB")
        top = shot.crop((0, 0, shot.width, min(shot.height, shot.width * CELL_H // CELL_W)))
        top.thumbnail((CELL_W, CELL_H))
        draw.text((x + 4, y + 3), path.name, fill="black")
        sheet.paste(top, (x, y + LABEL))
    sheet.save(out)


if __name__ == "__main__":
    main()
