"""Structural QA for the generated SporeM3 mushroom icons.

Cannot rely on the vision endpoint, so assert the artwork's invariants
directly from the pixels at every emitted size.
"""
import os

from PIL import Image

OUT = os.path.dirname(os.path.abspath(__file__))
RED = (0xDD, 0x1E, 0x28)
WHITE = (0xFE, 0xFE, 0xFE)
CREAM = (0xF7, 0xF3, 0xEC)
BAND = (0xEE, 0xE4, 0xD4)

SIZES = [256, 128, 64, 48, 32, 16]


def near(px, ref, tol=26):
    return abs(px[0] - ref[0]) < tol and abs(px[1] - ref[1]) < tol and abs(px[2] - ref[2]) < tol


def classify(px):
    if px[3] < 40:
        return "."
    if near(px, RED, 60):
        return "R"
    if near(px, WHITE, 10):
        return "W"
    if near(px, BAND, 16):
        return "B"
    if near(px, CREAM, 14):
        return "C"
    return "?"


print(f"{'size':>5} {'bbox_in_canvas':>22} {'red%':>6} {'white%':>7} {'unknown%':>9} {'sym':>5}")
ok = True

for s in SIZES:
    p = os.path.join(OUT, f"sporem3-mushroom-{s}.png")
    im = Image.open(p).convert("RGBA")
    px = list(im.get_flattened_data())
    w, h = im.size

    opaque = [(i, c) for i, c in enumerate(px) if c[3] > 40]
    if not opaque:
        print(f"{s:>5} EMPTY")
        ok = False
        continue
    xs = [i % w for i, _ in opaque]
    ys = [i // w for i, _ in opaque]
    bbox = (min(xs), min(ys), max(xs), max(ys))

    cls = [classify(c) for c in px]
    n_op = len(opaque)
    r = 100.0 * cls.count("R") / n_op
    wt = 100.0 * cls.count("W") / n_op
    unk = 100.0 * cls.count("?") / n_op

    # silhouette symmetry: for each opaque pixel, is the mirror (about the
    # vertical centre of the bbox) also opaque?
    cx2 = bbox[0] + bbox[2]
    asym = 0
    for i, _ in opaque:
        x, y = i % w, i // w
        mx = cx2 - x
        if 0 <= mx < w and px[y * w + mx][3] <= 40:
            asym += 1
    sym = 100.0 * (1 - asym / n_op)

    print(f"{s:>5} {str(bbox):>22} {r:6.1f} {wt:7.1f} {unk:9.1f} {sym:5.1f}")
    if unk > (20 if s <= 16 else 12):
        print(f"      !! {unk:.1f}% unrecognised colour")
        ok = False
    if sym < 88:
        print(f"      !! silhouette asymmetric ({sym:.1f}%)")
        ok = False
    if r < 25:
        print(f"      !! too little cap red ({r:.1f}%)")
        ok = False
    if wt < 12:
        print(f"      !! too little white ({wt:.1f}%)")
        ok = False

print()
print("QA:", "PASS" if ok else "FAIL")

# ---- ASCII render of the 16px icon so the shape is auditable in text ----
im16 = Image.open(os.path.join(OUT, "sporem3-mushroom-16.png")).convert("RGBA")
print("\n16px, one char per pixel:")
for y in range(im16.size[1]):
    row = "".join(classify(im16.getpixel((x, y))) for x in range(im16.size[0]))
    print("   ", row)

im32 = Image.open(os.path.join(OUT, "sporem3-mushroom-32.png")).convert("RGBA")
print("\n32px, one char per pixel:")
for y in range(im32.size[1]):
    row = "".join(classify(im32.getpixel((x, y))) for x in range(im32.size[0]))
    print("   ", row)
