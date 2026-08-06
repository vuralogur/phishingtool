"""Tier 2 - QR-code phishing ("quishing") detection.

Attackers put the malicious link inside a QR image so no clickable URL is in
the text for filters to catch. We decode QR codes from image attachments and
from inline data: images in the HTML body, then judge the embedded URL.

Decoding backend is optional and tried in order: OpenCV (no native DLL on
Windows) then pyzbar+Pillow. If neither is installed we simply skip - the rest
of the analyzer is unaffected.
"""
from __future__ import annotations
import base64
import re

from ..indicators import Indicator
from ..util import registered_domain, is_ip, levenshtein
from .urls import SHORTENERS

_IMG_EXT = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "tif"}
_DATA_IMG = re.compile(r"data:image/[a-z.+-]+;base64,([A-Za-z0-9+/=\s]+)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _decode_cv2(data: bytes):
    try:
        import numpy as np  # type: ignore
        import cv2  # type: ignore
    except Exception:
        return None  # backend absent
    try:
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            return []
        det = cv2.QRCodeDetector()
        try:
            ok, vals, _, _ = det.detectAndDecodeMulti(img)
            if ok and vals:
                return [v for v in vals if v]
        except Exception:
            pass
        val, _, _ = det.detectAndDecode(img)
        return [val] if val else []
    except Exception:
        return []


def _decode_pyzbar(data: bytes):
    try:
        import io
        from PIL import Image  # type: ignore
        from pyzbar.pyzbar import decode  # type: ignore
    except Exception:
        return None  # backend absent
    try:
        img = Image.open(io.BytesIO(data))
        return [r.data.decode("utf-8", "replace") for r in decode(img) if r.data]
    except Exception:
        return []


def _decode(data: bytes):
    """Return list of decoded strings, or None if no backend is available."""
    for backend in (_decode_cv2, _decode_pyzbar):
        res = backend(data)
        if res is not None:
            return res
    return None


def _image_blobs(email):
    """Yield raw image bytes from attachments and inline data: URIs."""
    for att in email.attachments:
        if att.payload and (att.ext in _IMG_EXT or att.content_type.lower().startswith("image/")):
            yield att.payload
    for m in _DATA_IMG.findall(email.html_body or ""):
        try:
            yield base64.b64decode(re.sub(r"\s+", "", m), validate=False)
        except Exception:
            continue


def _judge_url(url: str, brands: dict, sus_tlds: set):
    """Return (severity, weight, id, note) for a decoded URL, or None if benign-looking."""
    m = re.match(r"[a-z]+://([^/\s]+)", url, re.IGNORECASE)
    host = (m.group(1).split("@")[-1].split(":")[0] if m else "").lower()
    rdom = registered_domain(host)
    reasons = []
    if is_ip(host):
        reasons.append("ciplak IP")
    if rdom in SHORTENERS:
        reasons.append("kisaltici")
    tld = rdom.rsplit(".", 1)[-1] if "." in rdom else ""
    if tld and tld in sus_tlds:
        reasons.append("supheli TLD ." + tld)
    if "xn--" in host:
        reasons.append("punycode/IDN")
    for _brand, domains in brands.items():
        for legit in domains:
            if 0 < levenshtein(rdom, legit) <= 2 and rdom not in domains:
                reasons.append("marka taklidi ~" + legit)
                break
    return reasons


def run(email, online=False, ctx=None):
    ctx = ctx or {}
    brands = ctx.get("brands", {})
    sus_tlds = ctx.get("suspicious_tlds", set())
    out = []
    seen = set()

    for data in _image_blobs(email):
        decoded = _decode(data)
        if not decoded:  # None (no backend) or [] (no QR) - nothing to report
            continue
        for text in decoded:
            if not text or not _URL_RE.match(text.strip()):
                continue
            url = text.strip()
            if url in seen:
                continue
            seen.add(url)
            reasons = _judge_url(url, brands, sus_tlds)
            short = url[:80] + ("..." if len(url) > 80 else "")
            if reasons:
                out.append(Indicator("qr_suspicious_url", "attachment", "high", 18,
                    "QR koddaki URL supheli (" + ", ".join(reasons) + "): " + short,
                    "Quishing - kotu link filtrelerden kacmak icin QR goruntusune saklanmis."))
            else:
                out.append(Indicator("qr_code_url", "attachment", "medium", 10,
                    "Resimde URL tasiyan QR kod: " + short,
                    "E-postadaki QR kodun icinde link var; metinde gorunmez, dogrudan denetlenemez."))
    return out
