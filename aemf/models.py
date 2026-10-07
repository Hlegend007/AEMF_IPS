from dataclasses import dataclass, field
from typing import List, Optional, Tuple

@dataclass
class Fragment:
    seq: int
    payload: bytes
    timestamp: float
    ack: int = 0
    flags: str = ""

@dataclass
class Session:
    key: Tuple
    protocol: str
    fragments: List[Fragment] = field(default_factory=list)
    total_bytes: int = 0
    last_seen: float = 0.0
    status: str = "incomplete"
    fin_seen: bool = False
    source_ip: str = ""
    source_mac: str = ""
    dst_port: Optional[int] = None

@dataclass
class Detection:
    malicious: bool
    attack_type: str
    confidence: str
    reason: str
    signature: Optional[str]
    entropy: float
    raw_payload: bytes
    decoded_payload: str
