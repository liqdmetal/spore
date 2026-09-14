"""Generate the original SporeM3 mushroom icon set.

Original artwork (no third-party font, no game character): a generic
Amanita-style mushroom -- domed red cap with cream spots, white/cream stem.

Method
------
* Draw supersampled masters on a 1024px master grid (LANCZOS downsample).
* `simple=True` master drops the sub-pixel features (4th spot, deep shadow
  line) and thickens the stem -- used for 16px so the mark stays legible
  instead of turning to mush.
* Every size is alpha-cropped and re-framed to fill its canvas with an even
  ~5% margin, so 16px gets the same visual weight as 256px.

Palette sampled from the accepted brand assets:
  red   #DD1E28   (SporeM3 red)
  deep  #A8141C   (cap shadow)
  white #FEFEFE
  cream #F7F3EC
  dark  #0C1010   (brand background)
"""

import os

from PIL import Image, ImageDraw, ImageFont

OUT = os.path.dirname(os.path.abspath(__file__))

RED = (0xDD, 0x1E, 0x28, 255)
WHITE = (0xFE, 0xFE, 0xFE, 255)
CREAM = (0xF7, 0xF3, 0xEC, 255)
BAND = (0xEE, 0xE4, 0xD4, 255)
DARK = (0x0C, 0x10, 0x10, 255)

MASTER = 1024
SS = 4

CAP_CX = 512
CAP_HW = 436
CAP_BASE = 596
CAP_H = 448
STEM_TOP_Y = 600
STEM_BOT_Y = 920

# Full-detail spots: (dx from centre, y, radius)
SPOTS_FULL = [
    (-140, 336, 116),
    (204, 402, 84),
    (-232, 472, 60),
]
# Simplified spots for 16px: two, large, well inside the cap edge.
SPOTS_SIMPLE = [
    (-140, 336, 128),
    (198, 378, 100),
]


def draw_master(ss: int = 1, simple: bool = False) -> Image.Image:
    n = MASTER * ss
    im = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(im, "RGBA")

    def S(v: float) -> float:
        return v * ss

    cx, hw = S(CAP_CX), S(CAP_HW)
    base, ch = S(CAP_BASE), S(CAP_H)

    # cap: top half of an ellipse resting its base on CAP_BASE
    d.pieslice((cx - hw, base - ch, cx + hw, base + ch), 180, 360, fill=RED)
    d.rounded_rectangle(
        (cx - hw * 0.995, S(CAP_BASE - 128), cx + hw * 0.995, base),
        radius=S(52),
        fill=RED,
    )

    # cap underside
    if simple:
        d.rounded_rectangle(
            (cx - hw * 0.86, base - S(4), cx + hw * 0.86, base + S(40)),
            radius=S(22),
            fill=BAND,
        )
    else:
        d.rounded_rectangle(
            (cx - hw * 0.86, base - S(12), cx + hw * 0.86, base + S(50)),
            radius=S(26),
            fill=BAND,
        )

    # stem: tapered with a rounded base
    top_hw = S(124 if simple else 112)
    bot_hw = S(148 if simple else 140)
    ty, by = S(STEM_TOP_Y), S(STEM_BOT_Y)
    d.polygon(
        [(cx - top_hw, ty), (cx + top_hw, ty), (cx + bot_hw, by), (cx - bot_hw, by)],
        fill=WHITE,
    )
    d.ellipse((cx - bot_hw, by - S(46), cx + bot_hw, by + S(46)), fill=WHITE)

    if not simple:
        d.polygon(
            [
                (cx + top_hw * 0.42, ty),
                (cx + top_hw, ty),
                (cx + bot_hw, by),
                (cx + bot_hw * 0.52, by),
            ],
            fill=CREAM,
        )

    for dx, y, r in (SPOTS_SIMPLE if simple else SPOTS_FULL):
        rr = S(r)
        px, py = cx + S(dx), S(y)
        d.ellipse((px - rr, py - rr * 0.86, px + rr, py + rr * 0.86), fill=WHITE)

    return im


def framed(master: Image.Image, size: int, margin_frac: float = 0.05) -> Image.Image:
    """Alpha-crop the art and re-centre it to fill a `size` canvas evenly."""
    art = master.crop(master.getbbox())
    m = max(1, round(size * margin_frac))
    inner = max(1, size - 2 * m)
    aw, ah = art.size
    scale = inner / max(aw, ah)
    nw, nh = max(1, round(aw * scale)), max(1, round(ah * scale))
    art = art.resize((nw, nh), Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.alpha_composite(art, ((size - nw) // 2, (size - nh) // 2))
    return canvas


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    full = draw_master(ss=SS).resize((MASTER, MASTER), Image.LANCZOS)
    simple = draw_master(ss=SS, simple=True).resize((MASTER, MASTER), Image.LANCZOS)

    sizes = [256, 128, 64, 48, 32, 16]
    made = {}
    for s in sizes:
        icon = framed(simple if s <= 24 else full, s)
        icon.save(os.path.join(OUT, f"sporem3-mushroom-{s}.png"))
        made[s] = icon
        print(f"wrote sporem3-mushroom-{s}.png")

    made[256].save(
        os.path.join(OUT, "sporem3-mushroom.ico"),
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("wrote sporem3-mushroom.ico")

    # ---- review sheet ------------------------------------------------------
    W, H = 1440, 560
    sheet = Image.new("RGBA", (W, H), DARK)
    ds = ImageDraw.Draw(sheet, "RGBA")
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 20)
        small = ImageFont.truetype("DejaVuSans.ttf", 16)
    except OSError:
        font = small = ImageFont.load_default()

    ds.text((40, 24), "SporeM3 mushroom icon set - original artwork", font=font, fill=WHITE)
    sheet.alpha_composite(made[256], (40, 80))

    x = 340
    ds.text((x, 80), "native size (1:1)", font=small, fill=CREAM)
    cy = 300
    for s in [64, 48, 32, 16]:
        sheet.alpha_composite(made[s], (x, cy - s // 2))
        ds.text((x, cy + 130), f"{s}px", font=small, fill=CREAM)
        x += s + 56

    x = 340
    ds.text((x, 380), "zoomed x8 / x4 / x2 (nearest)", font=small, fill=CREAM)
    zy = 430
    for s, z in [(16, 8), (32, 4), (64, 2)]:
        sheet.alpha_composite(made[s].resize((s * z, s * z), Image.NEAREST), (x, zy))
        x += s * z + 40

    sheet.save(os.path.join(OUT, "sporem3-mushroom-preview.png"))
    print("wrote sporem3-mushroom-preview.png")


if __name__ == "__main__":
    main()
