"""Writes the demo files the screenshot accounts upload, into OUT/alice,
OUT/bob and OUT/carol. Usage: python3 make-files.py OUT"""

import io
import struct
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path


def pdf(title, lines):
    def esc(text):
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    ops = ["BT", "/F1 22 Tf", "72 700 Td", "(%s) Tj" % esc(title), "/F1 12 Tf"]
    for line in lines:
        ops += ["0 -24 Td", "(%s) Tj" % esc(line)]
    ops.append("ET")
    content = "\n".join(ops).encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"
        b" /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def png(width, height, top, bottom):
    rows = bytearray()
    for y in range(height):
        t = y / (height - 1)
        pixel = bytes(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
        rows += b"\x00" + pixel * width

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b"")


def tar_gz(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def zip_of(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def main():
    out = Path(sys.argv[1])
    harbor = png(640, 400, (70, 130, 180), (230, 196, 140))
    garden = png(640, 400, (120, 170, 90), (40, 90, 50))
    sunset = png(640, 400, (250, 160, 90), (90, 60, 130))
    notes = (
        "Planning meeting\n\n"
        "- Move the photo archive to the new server\n"
        "- Share the quarterly report with the partners\n"
        "- Review who can upload to the reports folder\n"
    ).encode()
    files = {
        "alice": {
            "quarterly-report.pdf": pdf("Quarterly report", ["Revenue grew in every region.", "Details follow on the next pages."]),
            "meeting-notes.txt": notes,
            "harbor.png": harbor,
            "garden.png": garden,
            "site-photos.zip": zip_of([("harbor.png", harbor), ("garden.png", garden), ("sunset.png", sunset), ("captions.txt", b"Harbor, garden and sunset.\n")]),
            "site-backup.tar.gz": tar_gz([("site/index.html", b"<!doctype html><title>Site</title>\n"), ("site/css/style.css", b"body { margin: 0; }\n"), ("site/images/harbor.png", harbor)]),
        },
        "bob": {
            "contract-draft.pdf": pdf("Contract draft", ["For review by the partners."]),
            "price-list.csv": b"item,price\nhosting,120\nsupport,80\n",
        },
        "carol": {
            "monthly-summary.pdf": pdf("Monthly summary", ["Uploads and downloads by account."]),
        },
    }
    for account, named in files.items():
        folder = out / account
        folder.mkdir(parents=True, exist_ok=True)
        for name, data in named.items():
            (folder / name).write_bytes(data)


if __name__ == "__main__":
    main()
