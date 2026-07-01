#!/usr/bin/env python3
"""Generate optiCombat UI assets from assets/branding source PNGs."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "optiCombat"
BRAND = ROOT / "assets" / "branding"

SRC_SHIELD = BRAND / "optiCombat_emblem_source.png"
SRC_SHIELD_HERO = ROOT / "shield optiCOMBAT.png"
SRC_WORDMARK = BRAND / "optiCombat_logo_horizontal.png"


def pick_shield_source() -> Path:
    """Emblème Combat Aqua officiel (assets/branding)."""
    if SRC_SHIELD.exists():
        return SRC_SHIELD
    if SRC_SHIELD_HERO.exists():
        return SRC_SHIELD_HERO
    raise SystemExit(f"Missing shield source: {SRC_SHIELD} or {SRC_SHIELD_HERO}")


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


def trim_alpha(im: Image.Image, pad_ratio: float = 0.04) -> Image.Image:
    """Recadre sur les pixels visibles (alpha), sans couper les zones sombres du bouclier."""
    im = im.convert("RGBA")
    bbox = im.getbbox()
    if not bbox:
        return im
    pad = max(8, int(min(im.size) * pad_ratio))
    x0, y0, x1, y1 = bbox
    return im.crop(
        (
            max(0, x0 - pad),
            max(0, y0 - pad),
            min(im.size[0], x1 + pad),
            min(im.size[1], y1 + pad),
        )
    )


def _bg_color_from_corners(im: Image.Image) -> tuple[int, int, int]:
    w, h = im.size
    px = im.load()
    samples = [
        px[0, 0],
        px[w - 1, 0],
        px[0, h - 1],
        px[w - 1, h - 1],
        px[w // 2, 0],
        px[w // 2, h - 1],
        px[0, h // 2],
        px[w - 1, h // 2],
    ]
    return tuple(sum(c[i] for c in samples) // len(samples) for i in range(3))


def _matches_matte(
    r: int, g: int, b: int, a: int, bg: tuple[int, int, int], tolerance: int
) -> bool:
    if a < 8:
        return True
    return (
        abs(r - bg[0]) <= tolerance
        and abs(g - bg[1]) <= tolerance
        and abs(b - bg[2]) <= tolerance
    )


def remove_matte_background(im: Image.Image, tolerance: int = 16) -> Image.Image:
    """Retire uniquement le fond connecte aux bords (preserve gris/rouge interieurs)."""
    from collections import deque

    im = im.convert("RGBA")
    w, h = im.size
    px = im.load()
    bg = _bg_color_from_corners(im)
    visited = bytearray(w * h)
    q: deque[tuple[int, int]] = deque()

    def idx(x: int, y: int) -> int:
        return y * w + x

    def try_seed(x: int, y: int) -> None:
        i = idx(x, y)
        if visited[i]:
            return
        r, g, b, a = px[x, y]
        if _matches_matte(r, g, b, a, bg, tolerance):
            visited[i] = 1
            q.append((x, y))

    for x in range(w):
        try_seed(x, 0)
        try_seed(x, h - 1)
    for y in range(h):
        try_seed(0, y)
        try_seed(w - 1, y)

    while q:
        x, y = q.popleft()
        for nx, ny in ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)):
            if nx < 0 or ny < 0 or nx >= w or ny >= h:
                continue
            i = idx(nx, ny)
            if visited[i]:
                continue
            r, g, b, a = px[nx, ny]
            if _matches_matte(r, g, b, a, bg, tolerance):
                visited[i] = 1
                q.append((nx, ny))

    out = im.copy()
    opx = out.load()
    for y in range(h):
        for x in range(w):
            if visited[idx(x, y)]:
                opx[x, y] = (0, 0, 0, 0)
    return out


def load_shield_hero() -> Image.Image:
    """Bouclier accueil — fond transparent, couleurs interieures preservees."""
    src = pick_shield_source()
    raw = Image.open(src).convert("RGBA")
    emblem = remove_matte_background(raw, tolerance=14)
    emblem = trim_alpha(emblem, pad_ratio=0.05)
    return add_margin(emblem, ratio=0.08)


def load_emblem() -> Image.Image:
    src = pick_shield_source()
    emblem = remove_matte_background(Image.open(src).convert("RGBA"), tolerance=14)
    emblem = trim_alpha(emblem, pad_ratio=0.05)
    return add_margin(emblem, ratio=0.06)


def load_wordmark() -> Image.Image:
    if not SRC_WORDMARK.exists():
        fallback = BRAND / "optiCombat_logo_wordmark.png"
        if not fallback.exists():
            raise SystemExit(f"Missing wordmark source: {SRC_WORDMARK}")
        raw = Image.open(fallback).convert("RGBA")
    else:
        raw = Image.open(SRC_WORDMARK).convert("RGBA")
    wordmark = remove_matte_background(raw, tolerance=20)
    wordmark = trim_alpha(wordmark, pad_ratio=0.03)
    return add_margin(wordmark, ratio=0.03)


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


def fit_banner_cover(
    im: Image.Image,
    width: int,
    height: int,
) -> Image.Image:
    """Remplit toute la bannière (recadrage) — occupe 100 % de la zone d'affichage."""
    trimmed = trim_content(im.convert("RGBA"))
    iw, ih = trimmed.size
    scale = max(width / iw, height / ih)
    nw, nh = max(1, int(iw * scale)), max(1, int(ih * scale))
    scaled = trimmed.resize((nw, nh), Image.Resampling.LANCZOS)
    x = max(0, (nw - width) // 2)
    y = max(0, (nh - height) // 2)
    return scaled.crop((x, y, x + width, y + height))


def shield_circle_bounds(im: Image.Image) -> tuple[int, int, int, int]:
    """BBox du cercle décoratif autour du bouclier (zone gauche du wordmark)."""
    im = im.convert("RGBA")
    px = im.load()
    w, h = im.size
    xs: list[int] = []
    ys: list[int] = []
    limit = int(w * 0.42)
    for y in range(h):
        for x in range(limit):
            r, g, b, a = px[x, y]
            if a > 25 and b > 110 and g > 70 and (b - r) > 15:
                xs.append(x)
                ys.append(y)
    if not xs:
        return 0, 0, w - 1, h - 1
    return min(xs), min(ys), max(xs), max(ys)


def fit_banner_home(
    im: Image.Image,
    width: int,
    height: int,
    pad_px: int = 10,
) -> Image.Image:
    """Logo accueil transparent, proportions conservées, cercle visible, aligné à droite."""
    trimmed = trim_alpha(im.convert("RGBA"), pad_ratio=0.02)
    iw, ih = trimmed.size
    _, cy0, _, cy1 = shield_circle_bounds(trimmed)
    ring_pad = max(4, int((cy1 - cy0 + 1) * 0.06))
    cy0 = max(0, cy0 - ring_pad)
    cy1 = min(ih - 1, cy1 + ring_pad)
    circle_h = cy1 - cy0 + 1

    scale = (height - 2 * pad_px) / circle_h
    max_w = int(width * 0.72)
    if iw * scale > max_w:
        scale = max_w / iw

    nw, nh = max(1, int(iw * scale)), max(1, int(ih * scale))
    scaled = trimmed.resize((nw, nh), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    x = width - nw
    if nh > height:
        y = int(pad_px - cy0 * scale)
        y = max(height - nh, min(0, y))
    else:
        y = (height - nh) // 2
    canvas.paste(scaled, (x, y), scaled)
    return canvas


def composite_app_icon(emblem: Image.Image, size: int = 256) -> Image.Image:
    """Emblème pour .ico (fond navy discret, bouclier bien visible)."""
    emblem = add_margin(trim_content(emblem), ratio=0.02)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bg = Image.new("RGBA", (size, size), (14, 26, 34, 255))
    radius = max(2, int(size * 0.18))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    canvas.paste(bg, (0, 0), mask)

    margin_ratio = 0.06 if size >= 128 else 0.05 if size >= 48 else 0.04
    margin = max(1, int(size * margin_ratio))
    inner = size - margin * 2
    iw, ih = emblem.size
    scale = min(inner / iw, inner / ih)
    nw, nh = max(1, int(iw * scale)), max(1, int(ih * scale))
    em = emblem.resize((nw, nh), Image.Resampling.LANCZOS)
    canvas.paste(em, ((size - nw) // 2, (size - nh) // 2), em)
    return canvas


def emblem_badge(emblem: Image.Image, size: int, margin_ratio: float = 0.02) -> Image.Image:
    """Emblème seul, fond transparent — sidebar et hero (bouclier lisible)."""
    return fit_square(add_margin(trim_content(emblem), ratio=0.02), size, margin_ratio=margin_ratio)


def resize_icon_layer(source: Image.Image, size: int) -> Image.Image:
    layer = composite_app_icon(source, size)
    resample = Image.Resampling.NEAREST if size <= 24 else Image.Resampling.LANCZOS
    if layer.size != (size, size):
        layer = layer.resize((size, size), resample)
    return layer.convert("RGBA")


def save_ico(path: Path, emblem: Image.Image, sizes: tuple[int, ...] = (16, 32, 48, 64, 128, 256)) -> None:
    """ICO Windows multi-resolutions (16–256 px) pour Explorateur et installateur."""
    ordered = sorted(sizes)
    layers = [resize_icon_layer(emblem, s) for s in ordered]
    layers[-1].save(
        path,
        format="ICO",
        sizes=[(s, s) for s in ordered],
        append_images=layers[:-1],
    )


def main() -> None:
    BRAND.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    emblem = load_emblem()
    shield_hero = load_shield_hero()
    wordmark = load_wordmark()

    emblem.save(BRAND / "optiCombat_emblem_transparent.png")

    wordmark.save(BRAND / "optiCombat_logo_wordmark.png")

    hero_size = min(1024, max(512, max(shield_hero.size)))
    emblem_badge(shield_hero, hero_size, margin_ratio=0.01).save(OUT / "optiCombat_hero.png")
    emblem_badge(emblem, 256, margin_ratio=0.02).save(OUT / "optiCombat_shield.png")
    fit_banner_home(wordmark, 1680, 420, pad_px=10).save(OUT / "optiCombat.png")
    fit_square(emblem, 256, margin_ratio=0.08).save(BRAND / "optiCombat_emblem_256.png")

    save_ico(OUT / "optiCombat.ico", emblem)
    save_ico(OUT / "ico.ico", emblem)

    print(
        "Brand assets OK — shield: "
        + pick_shield_source().name
        + " + "
        + (SRC_WORDMARK.name if SRC_WORDMARK.exists() else "wordmark fallback")
    )


if __name__ == "__main__":
    main()
