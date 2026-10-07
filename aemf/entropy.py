import math
from collections import Counter

def shannon_entropy(data):
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())
