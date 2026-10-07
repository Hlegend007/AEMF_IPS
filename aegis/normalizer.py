import base64
import binascii
import html
import re
import time
import urllib.parse

class RecursiveNormalizer:
    """URL/Base64/hex/HTML recursive decoder with PDF safety limits."""

    URL_RE = re.compile(r"%[0-9A-Fa-f]{2}")
    HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
    B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

    def __init__(self, max_iterations=10, timeout=0.100):
        self.max_iterations = max_iterations
        self.timeout = timeout

    def _try_url(self, s):
        if not self.URL_RE.search(s):
            return None
        out = urllib.parse.unquote(s)
        return out if out != s else None

    def _try_hex(self, s):
        t = s.strip()
        if len(t) < 2 or len(t) % 2 or not self.HEX_RE.fullmatch(t):
            return None
        try:
            out = bytes.fromhex(t).decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            return None
        return out if out != s else None

    def _try_b64(self, s):
        t = s.strip()
        if len(t) < 4 or len(t) % 4 or not self.B64_RE.fullmatch(t):
            return None
        try:
            raw = base64.b64decode(t, validate=True)
            out = raw.decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        # Avoid treating arbitrary short English text as Base64.
        if not any(c in t for c in "=+/") and len(t) < 8:
            return None
        return out if out != s else None

    def normalize(self, payload):
        start = time.perf_counter()
        if isinstance(payload, bytes):
            current = payload.decode("utf-8", errors="replace")
        else:
            current = str(payload)
        warnings = []
        layers = []

        for _ in range(self.max_iterations):
            if time.perf_counter() - start > self.timeout:
                warnings.append("normalization_timeout")
                break

            changed = False
            for name, decoder in (
                ("url", self._try_url),
                ("hex", self._try_hex),
                ("base64", self._try_b64),
            ):
                try:
                    decoded = decoder(current)
                except Exception:
                    decoded = None
                if decoded is not None and decoded != current:
                    current = decoded
                    layers.append(name)
                    changed = True
                    break

            if not changed:
                # HTML entities/tags are a useful normalization step from the
                # PDF's "HTML and other decoders" wording.
                decoded_html = html.unescape(current)
                if decoded_html != current:
                    current = decoded_html
                    layers.append("html")
                    changed = True

            if not changed:
                break
        else:
            warnings.append("max_iterations_reached")

        return current, layers, warnings
