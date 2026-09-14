"""QR code rendering helpers.

Uses :mod:`segno` (pure-Python, MIT licensed, no native deps) to render
inline SVG suitable for embedding directly in HTML responses without any
client-side JS dependency. SVG keeps the payload tiny and scales cleanly.
"""

from __future__ import annotations

import io

import segno


def render_svg(data: str, *, scale: int = 6, border: int = 4) -> str:
    """Return an inline SVG string encoding ``data`` as a QR code.

    The returned markup is a self-contained ``<svg>`` element with no
    XML/DOCTYPE prologue, so it can be dropped straight into HTML.
    """
    buf = io.BytesIO()
    qr = segno.make(data, error="m")
    qr.save(
        buf,
        kind="svg",
        scale=scale,
        border=border,
        xmldecl=False,
        svgns=True,
        omitsize=True,
    )
    return buf.getvalue().decode("ascii")


__all__ = ["render_svg"]
