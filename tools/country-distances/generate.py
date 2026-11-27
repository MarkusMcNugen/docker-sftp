"""Writes the table of distances between countries that the sign-in check
uses for impossible travel: for each pair of countries, the great-circle
distance in km between their nearest border points, from Natural Earth's
1:50m country boundaries (public domain). Neighbors are 0 km apart.

The input is ne_50m_admin_0_countries.geojson from
https://github.com/nvkelso/natural-earth-vector, tag v5.1.2; any other file
is refused by its SHA-256. Countries are keyed by ISO_A2_EH; the three
features without a code (Somaliland, N. Cyprus, Siachen Glacier) are left
out.

The output is little-endian: the magic b"CTDK", a u16 count n, n two-letter
codes in ascending order, then an n by n matrix of u16 km, row by row.
Needs numpy. Usage: python generate.py BOUNDARIES.geojson OUT.bin"""

import hashlib
import json
import struct
import sys
from pathlib import Path

import numpy

SHA256 = "3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb"
EARTH_KM = 6371.0088


def rings(geometry):
    if geometry["type"] == "Polygon":
        yield from geometry["coordinates"]
    elif geometry["type"] == "MultiPolygon":
        for polygon in geometry["coordinates"]:
            yield from polygon
    else:
        raise ValueError(f"unexpected geometry {geometry['type']}")


def unit_vectors(points):
    lon, lat = numpy.radians(numpy.asarray(points, dtype=float)).T
    return numpy.stack([numpy.cos(lat) * numpy.cos(lon), numpy.cos(lat) * numpy.sin(lon), numpy.sin(lat)], axis=1)


def nearest_km(a, b):
    best = -1.0
    for start in range(0, len(a), 4096):
        best = max(best, float((a[start:start + 4096] @ b.T).max()))
    return EARTH_KM * float(numpy.arccos(min(1.0, best)))


def main():
    source, out = Path(sys.argv[1]), Path(sys.argv[2])
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        sys.exit(f"{source} has SHA-256 {digest}, not Natural Earth v5.1.2's {SHA256}")
    points = {}
    for feature in json.loads(data)["features"]:
        code = feature["properties"].get("ISO_A2_EH")
        if not code or code == "-99":
            continue
        for ring in rings(feature["geometry"]):
            points.setdefault(code, []).extend(point[:2] for point in ring)
    codes = sorted(points)
    vectors = {code: unit_vectors(points[code]) for code in codes}
    n = len(codes)
    matrix = numpy.zeros((n, n), dtype="<u2")
    for i in range(n):
        for j in range(i + 1, n):
            km = round(nearest_km(vectors[codes[i]], vectors[codes[j]]))
            matrix[i, j] = matrix[j, i] = km
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as table:
        table.write(b"CTDK" + struct.pack("<H", n) + "".join(codes).encode("ascii"))
        table.write(matrix.tobytes())
    print(f"{n} countries, {out.stat().st_size} B")


if __name__ == "__main__":
    main()
