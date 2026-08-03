"""QR rendering behavior for payment payloads."""

from __future__ import annotations

from blindport.core import qr


def test_render_svg_keeps_medium_error_correction_and_responsive_dimensions(monkeypatch) -> None:
    make = qr.segno.make
    options: dict[str, str] = {}

    def capture_make(data: str, **kwargs: str):
        options.update(kwargs)
        return make(data, **kwargs)

    monkeypatch.setattr(qr.segno, "make", capture_make)

    svg = qr.render_svg("LNBC1RESPONSIVE")

    assert options == {"error": "m"}
    assert 'viewBox="0 0 ' in svg
    assert " width=" not in svg.split(">", 1)[0]
    assert " height=" not in svg.split(">", 1)[0]
