#!/usr/bin/env python3
"""Rasterises `icon.svg` into `icon.png`.

The SVG is the source of truth; this exists because federation and older clients still ask
for a PNG, and shipping a hand-edited binary with no way to regenerate it is worse than
shipping the thirty lines that make it. Run from this directory: `python3 build_icon.py`.
"""

import struct
import zlib

SIZE = 512
SUPERSAMPLE = 4

PRIMARY = (0x3F, 0x63, 0xC9)
WHITE = (255, 255, 255)
ACCENT = (0x8E, 0xF0, 0xC5)

RADIUS = 116


def inside_rounded(x, y):
    if x < 0 or y < 0 or x > SIZE or y > SIZE:
        return False
    cx = min(max(x, RADIUS), SIZE - RADIUS)
    cy = min(max(y, RADIUS), SIZE - RADIUS)
    return (x - cx) ** 2 + (y - cy) ** 2 <= RADIUS**2


def on_segment(x, y, x1, y1, x2, y2, half_width):
    dx, dy = x2 - x1, y2 - y1
    length = dx * dx + dy * dy
    if length == 0:
        return (x - x1) ** 2 + (y - y1) ** 2 <= half_width**2
    t = ((x - x1) * dx + (y - y1) * dy) / length
    t = 0.0 if t < 0 else 1.0 if t > 1 else t
    px, py = x1 + t * dx, y1 + t * dy
    return (x - px) ** 2 + (y - py) ** 2 <= half_width**2


STEM = ((160, 156), (160, 356))
DIAGONAL = ((160, 356), (352, 156))
RIGHT = ((352, 156), (352, 356))
STROKE = 13


def colour_at(x, y):
    if (x - 352) ** 2 + (y - 156) ** 2 <= 46**2:
        return ACCENT
    for cx, cy in ((160, 156), (160, 356), (352, 356)):
        if (x - cx) ** 2 + (y - cy) ** 2 <= 34**2:
            return WHITE
    for segment in (STEM, DIAGONAL, RIGHT):
        if on_segment(x, y, *segment[0], *segment[1], STROKE):
            return WHITE
    if inside_rounded(x, y):
        return PRIMARY
    return None


def render():
    step = 1.0 / SUPERSAMPLE
    samples = SUPERSAMPLE * SUPERSAMPLE
    rows = []
    for py in range(SIZE):
        row = bytearray()
        row.append(0)
        for px in range(SIZE):
            counts = {}
            for sy in range(SUPERSAMPLE):
                y = py + (sy + 0.5) * step
                for sx in range(SUPERSAMPLE):
                    x = px + (sx + 0.5) * step
                    colour = colour_at(x, y)
                    if colour is not None:
                        counts[colour] = counts.get(colour, 0) + 1
            r = sum(c[0] * n for c, n in counts.items())
            g = sum(c[1] * n for c, n in counts.items())
            b = sum(c[2] * n for c, n in counts.items())
            covered = sum(counts.values())
            if covered == 0:
                row.extend((0, 0, 0, 0))
                continue
            row.extend(
                (
                    round(r / covered),
                    round(g / covered),
                    round(b / covered),
                    round(255 * covered / samples),
                )
            )
        rows.append(bytes(row))
    return b"".join(rows)


def chunk(kind, payload):
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def main():
    raw = render()
    header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    with open("icon.png", "wb") as handle:
        handle.write(png)


if __name__ == "__main__":
    main()
