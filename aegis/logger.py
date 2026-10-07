from pathlib import Path
from datetime import datetime, timezone
import binascii

class BlockLogger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append_block(self, mac, ip, attack_type, raw, decoded, confidence, reason):
        line = "|".join([
            self._ts(), "BLOCK", mac, ip or "-", attack_type,
            binascii.hexlify(raw).decode(), self._safe(decoded),
            confidence, self._safe(reason)
        ])
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def append_unblock(self, mac, admin, reason):
        line = "|".join([
            self._ts(), "UNBLOCK", mac, admin, self._safe(reason)
        ])
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def append_error(self, subject, message):
        line = "|".join([self._ts(), "ERROR", subject, self._safe(message)])
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    @staticmethod
    def _ts():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe(value):
        return str(value).replace("|", "/").replace("\n", " ")
