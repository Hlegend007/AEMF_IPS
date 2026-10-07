from dataclasses import dataclass
from pathlib import Path
import platform

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
BLOCK_LOG = LOG_DIR / "block.log"
SIGNATURES_FILE = DATA_DIR / "signatures.json"

@dataclass
class Settings:
    entropy_threshold: float = 4.8
    icmp_entropy_threshold: float = 7.5
    session_ttl: float = 30.0
    gc_interval: float = 5.0
    normalization_max_iterations: int = 10
    normalization_timeout: float = 0.100
    block_duration: int = 300
    persistent_blocks: bool = False
    cpu_target_percent: float = 10.0
    memory_target_mb: float = 100.0

    @property
    def is_linux(self) -> bool:
        return platform.system().lower() == "linux"

SETTINGS = Settings()
DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
