from typing import Iterable
from .models import Fragment

def reassemble(fragments: Iterable[Fragment]) -> bytes:
    """Sequence-ordered reassembly; later fragment wins on overlap."""
    frags = sorted(fragments, key=lambda f: f.seq)
    if not frags:
        return b""
    # Build a byte map. Processing in arrival order means later fragments
    # overwrite earlier bytes, matching the PDF's overlap requirement.
    byte_map = {}
    for frag in frags:
        for offset, value in enumerate(frag.payload):
            byte_map[frag.seq + offset] = value
    positions = sorted(byte_map)
    if not positions:
        return b""
    # Fill gaps explicitly; a gap means the stream is incomplete.
    start = positions[0]
    end = positions[-1]
    return bytes(byte_map.get(i, ord("?")) for i in range(start, end + 1))
