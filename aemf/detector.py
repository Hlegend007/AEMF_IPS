from .entropy import shannon_entropy
from .models import Detection
from .normalizer import RecursiveNormalizer

class DetectionEngine:
    def __init__(self, signature_db, settings):
        self.db = signature_db
        self.settings = settings
        self.normalizer = RecursiveNormalizer(
            settings.normalization_max_iterations,
            settings.normalization_timeout,
        )

    def analyze(self, raw_payload, protocol, dst_port=None):
        decoded, layers, warnings = self.normalizer.normalize(raw_payload)
        entropy = shannon_entropy(decoded)
        hits = self.db.match(decoded, protocol)

        entropy_threshold = self.settings.icmp_entropy_threshold if protocol == "ICMP" else self.settings.entropy_threshold
        entropy_hit = entropy > entropy_threshold
        large_icmp_hit = protocol == "ICMP" and len(raw_payload) > 200

        if hits:
            confidence = "HIGH"
            reason = "Signature match: " + ", ".join(h.name for h in hits)
            attack_type = "ICMP_TUNNEL" if protocol == "ICMP" else "HTTP_SPLITTER"
            malicious = True
            sig = hits[0].name
        elif entropy_hit:
            confidence = "MEDIUM"
            reason = f"Entropy {entropy:.3f} exceeds threshold {entropy_threshold:.3f}"
            attack_type = "ICMP_TUNNEL" if protocol == "ICMP" else "HTTP_SPLITTER"
            malicious = True
            sig = None
        elif large_icmp_hit:
            confidence = "MEDIUM"
            reason = f"ICMP payload size {len(raw_payload)} exceeds 200-byte lab threshold"
            attack_type = "ICMP_TUNNEL"
            malicious = True
            sig = None
        else:
            confidence = "LOW"
            reason = "No signature or entropy anomaly"
            attack_type = "NORMAL"
            malicious = False
            sig = None

        if warnings:
            reason += "; " + ", ".join(warnings)

        return Detection(malicious, attack_type, confidence, reason, sig, entropy, raw_payload, decoded), layers
