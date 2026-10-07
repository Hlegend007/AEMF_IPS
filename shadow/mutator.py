import base64
import binascii
import random
import codecs

def encode_layers(payload, layers):
    value = payload.encode("utf-8") if isinstance(payload, str) else payload
    for layer in layers:
        if layer == "base64":
            value = base64.b64encode(value).decode()
        elif layer == "hex":
            raw = value.encode("utf-8") if isinstance(value, str) else value
            value = binascii.hexlify(raw).decode()
        elif layer == "url":
            text = value.decode() if isinstance(value, bytes) else value
            # The PDF's mutation example percent-encodes every character.
            value = "".join(f"%{ord(ch):02X}" for ch in text)
        elif layer == "rot13":
            value = codecs.encode(value.decode() if isinstance(value, bytes) else value, "rot_13")
        elif layer == "none":
            pass
        else:
            raise ValueError(f"Unsupported encoding layer: {layer}")
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")

def fragment_payload(encoded, size=4, out_of_order=False, overlap=False):
    if size <= 0:
        raise ValueError("Fragment size must be positive")
    pieces = [encoded[i:i+size].encode() for i in range(0, len(encoded), size)]
    fragments = []
    seq = 0
    for p in pieces:
        fragments.append((seq, p))
        seq += len(p)
    if overlap and len(fragments) >= 2:
        # Create a small two-byte overlap while preserving a recoverable stream.
        s, p = fragments[1]
        fragments[1] = (max(0, s-2), p)
    if out_of_order:
        random.shuffle(fragments)
    return fragments
