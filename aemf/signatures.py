import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class Signature:
    name: str
    pattern: str
    description: str
    severity: str
    protocol: str
    compiled_pattern: Optional[re.Pattern] = None

class SignatureDB:
    def __init__(self, path):
        self.path = Path(path)
        self.signatures = []
        self.reload()

    def reload(self):
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        signatures = []
        for entry in raw:
            signature = Signature(**entry)
            try:
                signature.compiled_pattern = re.compile(signature.pattern)
            except re.error as exc:
                raise ValueError(f"Invalid signature pattern {signature.name!r}: {exc}") from exc
            signatures.append(signature)
        self.signatures = signatures

    def match(self, text, protocol):
        hits = []
        for sig in self.signatures:
            if sig.protocol not in ("BOTH", protocol):
                continue
            if sig.compiled_pattern is not None and sig.compiled_pattern.search(text):
                hits.append(sig)
        return hits
