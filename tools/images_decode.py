"""Decode one picture and write a downsized copy for a vision model.

Runs as its own process (``python -I images_decode.py <in> <out>
<max_pixels>``), started by tools.images.describe through the executor:
carved pictures are attacker-controllable bytes, often cut short, and a
decoder that crashes on one must take down nothing but this process. Only
Pillow and the standard library are imported; nothing of Atlas.

Rules: Pillow's decompression-bomb ceiling (``Image.MAX_IMAGE_PIXELS``)
stays at its default and is never disabled; a truncated file is an error
(``LOAD_TRUNCATED_IMAGES`` stays off), not a half picture; an animation
sends its first frame and says so. The picture is scaled to at most
``max_pixels`` and written as JPEG (no transparency) or PNG (with it).
One JSON line of metadata goes to stdout, never bytes; exit 0 on success,
2 on a decode error, 3 on bad arguments.
"""
from __future__ import annotations

import json
import math
import sys
import warnings

# The child's address space, so a decoder that runs away ends the child,
# never the host: a per-call guard of this process alone.
ADDRESS_SPACE_LIMIT = 2 * 1024 ** 3


def _limit_address_space() -> None:
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        wanted = ADDRESS_SPACE_LIMIT if hard == resource.RLIM_INFINITY else min(ADDRESS_SPACE_LIMIT, hard)
        if soft == resource.RLIM_INFINITY or soft > wanted:
            resource.setrlimit(resource.RLIMIT_AS, (wanted, hard))
    except Exception:  # noqa: BLE001 - a platform without the limit decodes without it
        pass


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(json.dumps({"ok": False, "error": "usage: images_decode.py <in> <out> <max_pixels>"}))
        return 3
    src, dst, max_pixels = argv[1], argv[2], int(argv[3])
    try:
        from PIL import Image
    except ImportError as e:  # pragma: no cover - the availability mark says so first
        print(json.dumps({"ok": False, "error": f"Pillow is not installed: {e}"}))
        return 2
    # Pillow warns between its bomb ceiling and twice it and decodes the
    # whole picture (hundreds of megabytes); here the warning is an error.
    warnings.simplefilter("error", Image.DecompressionBombWarning)
    try:
        with Image.open(src) as im:
            frames = int(getattr(im, "n_frames", 1) or 1)
            if frames > 1:
                im.seek(0)
            width, height = im.size
            source_format = str(im.format or "")
            if width * height > max_pixels:
                factor = math.sqrt(max_pixels / float(width * height))
                # A JPEG is decoded at a reduced scale (DCT scaling) toward
                # the target: the full picture is never held in memory.
                im.draft(None, (max(1, int(width * factor)), max(1, int(height * factor))))
            im.load()                       # decodes here; a truncated file raises
            scaled = im
            if im.size[0] * im.size[1] > max_pixels:
                factor = math.sqrt(max_pixels / float(im.size[0] * im.size[1]))
                size = (max(1, int(im.size[0] * factor)), max(1, int(im.size[1] * factor)))
                scaled = im.resize(size, Image.LANCZOS)
            transparent = scaled.mode in ("RGBA", "LA") or (scaled.mode == "P" and "transparency" in scaled.info)
            if transparent:
                scaled.convert("RGBA").save(dst, "PNG")
                media_type = "image/png"
            else:
                scaled.convert("RGB").save(dst, "JPEG", quality=85)
                media_type = "image/jpeg"
            sent_w, sent_h = scaled.size
    except Exception as e:  # noqa: BLE001 - the error is the result
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}))
        return 2
    print(json.dumps({"ok": True, "width": width, "height": height, "sent_width": sent_w, "sent_height": sent_h,
                      "frames": frames, "format": source_format, "media_type": media_type}))
    return 0


if __name__ == "__main__":
    _limit_address_space()
    sys.exit(main(sys.argv))
