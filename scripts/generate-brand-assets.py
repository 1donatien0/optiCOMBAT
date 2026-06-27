#!/usr/bin/env python3
"""Generate optiCombat UI assets from assets/branding source PNGs."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "optiCombat"
BRAND = ROOT / "assets" / "branding"

SRC_SHIELD = BRAND / "optiCombat_emblem_source.png"
SRC_WORDMARK = BRAND / "optiCombat_logo_horizontal.png"


def trim_content(im: Image.Image, threshold: int = 22) -> Image.Image:
    im = im.convert("RGBA")
    px = im.load()
    w, h = im.size
    min_x, min_y, max_x, max_y = w, h, 0, 0
    found = False
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a < 8:
                continue
            if max(r, g, b) > threshold:
                found = True
                min_x = min(min_x, x)
                min_y = min(min_y, y)
                max_x = max(max_x, x)
                max_y = max(max_y, y)
    if not found or max_x <= min_x or max_y <= min_y:
        return im
    pad = max(6, int(min(w, h) * 0.03))
    return im.crop(
        (
            max(0, min_x - pad),
            max(0, min_y - pad),
            min(w, max_x + pad + 1),
            min(h, max_y + pad + 1),
        )
    )


def add_margin(im: Image.Image, ratio: float = 0.10) -> Image.Image:
    im = im.convert("RGBA")
    w, h = im.size
    pad_x = max(4, int(w * ratio))
    pad_y = max(4, int(h * ratio))
    canvas = Image.new("RGBA", (w + pad_x * 2, h + pad_y * 2), (0, 0, 0, 0))
    canvas.paste(im, (pad_x, pad_y), im)
    return canvas


def fit_square(
    im: Image.Image,
    size: int,
    margin_ratio: float = 0.08,
    bg: tuple[int, int, int, int] | None = None,
) -> Image.Image:
    im = im.convert("RGBA")
    margin = max(3, int(size * margin_ratio))
    inner = size - margin * 2
    iw, ih = im.size
    scale = min(inner / iw, inner / ih)
    nw, nh = max(1, int(iw * scale)), max(1, int(ih * scale))
    scaled = im.resize((nw, nh), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (size, size), bg if bg is not None else (0, 0, 0, 0))
    canvas.paste(scaled, ((size - nw) // 2, (size - nh) // 2), scaled)
    return canvas


def remove_matte_background(im: Image.Image, tolerance: int = 24) -> Image.Image:
    """Retire le fond gris mat (sources fournies avec fond opaque)."""
    im = im.convert("RGBA")
    w, h = im.size
    px = im.load()
    samples = [
        px[0, 0],
        px[w - 1, 0],
        px[0, h - 1],
        px[w - 1, h - 1],
        px[w // 2, 0],
        px[w // 2, h - 1],
    ]
    bg = tuple(sum(c[i] for c in samples) // len(samples) for i in range(3))
    out = im.copy()
    opx = out.load()
    for y in range(h):
        for x in range(w):
            r, g, b, a = opx[x, y]
            if a < 8:
                continue
            if abs(r - bg[0]) <= tolerance and abs(g - bg[1]) <= tolerance and abs(b - bg[2]) <= tolerance:
                opx[x, y] = (0, 0, 0, 0)
    return out


def load_shield_hero() -> Image.Image:
    """Bouclier accueil — source avec fond gris conservé."""
    if not SRC_SHIELD.exists():
        return load_emblem()
    return add_margin(trim_content(Image.open(SRC_SHIELD).convert("RGBA")), ratio=0.02)


def load_emblem() -> Image.Image:
    if not SRC_SHIELD.exists():
        fallback = BRAND / "optiCombat_emblem_transparent.png"
        if not fallback.exists():
            raise SystemExit(f"Missing emblem source: {SRC_SHIELD}")
        return add_margin(trim_content(Image.open(fallback).convert("RGBA")), ratio=0.06)
    emblem = remove_matte_background(trim_content(Image.open(SRC_SHIELD).convert("RGBA")))
    return add_margin(emblem, ratio=0.06)


def load_wordmark() -> Image.Image:
    if not SRC_WORDMARK.exists():
        fallback = BRAND / "optiCombat_logo_wordmark.png"
        if not fallback.exists():
            raise SystemExit(f"Missing wordmark source: {SRC_WORDMARK}")
        return add_margin(trim_content(Image.open(fallback).convert("RGBA")), ratio=0.04)
    return add_margin(trim_content(Image.open(SRC_WORDMARK).convert("RGBA")), ratio=0.03)


def fit_banner(
    im: Image.Image,
    width: int,
    height: int,
    margin_ratio: float = 0.04,
) -> Image.Image:
    im = im.convert("RGBA")
    margin_x = max(4, int(width * margin_ratio))
    margin_y = max(4, int(height * margin_ratio))
    inner_w = width - margin_x * 2
    inner_h = height - margin_y * 2
    iw, ih = im.size
    scale = min(inner_w / iw, inner_h / ih)
    nw, nh = max(1, int(iw * scale)), max(1, int(ih * scale))
    scaled = im.resize((nw, nh), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    canvas.paste(scaled, ((width - nw) // 2, (height - nh) // 2), scaled)
    return canvas


def composite_app_icon(emblem: Image.Image, size: int = 256) -> Image.Image:
    """Emblème sur fond sombre arrondi (sidebar + .ico)."""
    emblem = add_margin(trim_content(emblem), ratio=0.04 if size >= 64 else 0.02)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bg = Image.new("RGBA", (size, size), (22, 22, 28, 255))
    radius = max(2, int(size * 0.20))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    canvas.paste(bg, (0, 0), mask)

    margin_ratio = 0.14 if size >= 128 else 0.11 if size >= 48 else 0.06 if size >= 32 else 0.04
    margin = max(1, int(size * margin_ratio))
    inner = size - margin * 2
    iw, ih = emblem.size
    scale = min(inner / iw, inner / ih)
    nw, nh = max(1, int(iw * scale)), max(1, int(ih * scale))
    em = emblem.resize((nw, nh), Image.Resampling.LANCZOS)
    canvas.paste(em, ((size - nw) // 2, (size - nh) // 2), em)
    return canvas


def resize_icon_layer(source: Image.Image, size: int) -> Image.Image:
    layer = composite_app_icon(source, size)
    resample = Image.Resampling.NEAREST if size <= 24 else Image.Resampling.LANCZOS
    if layer.size != (size, size):
        layer = layer.resize((size, size), resample)
    return layer.convert("RGBA")


def save_ico(path: Path, emblem: Image.Image, sizes: tuple[int, ...] = (16, 32, 48, 64, 128, 256)) -> None:
    ordered = sorted(sizes, reverse=True)
    layers = [resize_icon_layer(emblem, s) for s in ordered]
    layers[0].save(path, format="ICO", append_images=layers[1:])


def main() -> None:
    BRAND.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    emblem = load_emblem()
    shield_hero = load_shield_hero()
    wordmark = load_wordmark()

    emblem.save(BRAND / "optiCombat_emblem_transparent.png")

    wordmark.save(BRAND / "optiCombat_logo_wordmark.png")

    fit_square(shield_hero, 512, margin_ratio=0.06).save(OUT / "optiCombat_hero.png")
    composite_app_icon(emblem, 256).save(OUT / "optiCombat_shield.png")
    fit_banner(wordmark, 880, 220, margin_ratio=0.04).save(OUT / "optiCombat.png")
    fit_square(emblem, 256, margin_ratio=0.08).save(BRAND / "optiCombat_emblem_256.png")

    save_ico(OUT / "optiCombat.ico", emblem)
    save_ico(OUT / "ico.ico", emblem)

    print("Brand assets OK — sources: assets/branding/optiCombat_emblem_source.png + optiCombat_logo_horizontal.png")


if __name__ == "__main__":
    main()
