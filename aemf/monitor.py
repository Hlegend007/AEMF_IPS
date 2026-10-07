import platform
import threading
import time

from .detector import DetectionEngine
from .models import Fragment
from .prevention import PreventionEngine
from .reassembler import reassemble
from .state import StateTable

class AEMFMonitor:
    def __init__(self, settings, signature_db, logger, simulation=True):
        self.settings = settings
        self.state = StateTable(settings.session_ttl)
        self.detector = DetectionEngine(signature_db, settings)
        self.prevention = PreventionEngine(logger, simulation, settings.block_duration)
        self.stop_event = threading.Event()
        self.gc_thread = None
        self.sniff_thread = None

    def start_gc(self):
        def loop():
            while not self.stop_event.wait(self.settings.gc_interval):
                stale = self.state.collect_stale()
                removed = []
                for session in stale:
                    if session.protocol == "ICMP":
                        result = self._analyze_session(session)
                        if result:
                            self.print_result(result)
                    removed.append(session.key)
                self.prevention.expire()
                if removed:
                    print(f"[GC] removed {len(removed)} stale session(s)")
        self.gc_thread = threading.Thread(target=loop, daemon=True)
        self.gc_thread.start()

    def stop(self):
        self.stop_event.set()

    def process_fragment(self, key, protocol, fragment, ip, mac, complete=False, dst_port=None):
        session = self.state.add(key, protocol, fragment)
        session.source_ip = ip
        session.source_mac = mac
        session.dst_port = dst_port
        # Lazy analysis: only analyze when completion is signalled.
        if not complete and not fragment.flags and not fragment.payload.endswith(b"\n"):
            return None
        return self._analyze_session(session)

    def _analyze_session(self, session):
        session.status = "complete"
        raw = reassemble(session.fragments)
        session.status = "analyzing"
        detection, layers = self.detector.analyze(raw, session.protocol, session.dst_port)
        session.status = "complete"
        result = {
            "detection": detection,
            "layers": layers,
            "session_key": session.key,
            "fragments": len(session.fragments),
            "raw": raw,
        }
        if detection.malicious:
            try:
                self.prevention.block(
                    session.source_mac, session.source_ip, detection.attack_type, detection.raw_payload,
                    detection.decoded_payload, detection.confidence, detection.reason
                )
                result["blocked"] = True
            except Exception as exc:
                result["blocked"] = False
                result["prevention_error"] = str(exc)
        else:
            result["blocked"] = False
        self.state.pop(session.key)
        return result

    def start_live(self, iface=None):
        if platform.system().lower() != "linux":
            raise RuntimeError("Live AEMF capture is Linux-primary; use simulation mode on Windows.")
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise RuntimeError("Scapy is required for live mode") from exc

        self.start_gc()

        def handle(pkt):
            from scapy.layers.inet import IP, TCP, ICMP
            from scapy.layers.l2 import Ether
            now = time.time()
            if IP not in pkt:
                return
            ip = pkt[IP].src
            mac = pkt[Ether].src if Ether in pkt else "00:00:00:00:00:00"
            if ICMP in pkt:
                payload = bytes(pkt[ICMP].payload)
                icmp_type = int(getattr(pkt[ICMP], "type", 8) or 8)
                icmp_id = int(getattr(pkt[ICMP], "id", 0) or 0)
                key = (ip, icmp_type, icmp_id)
                if icmp_type in (0, 8):
                    seq = int(getattr(pkt[ICMP], "seq", 0) or 0)
                else:
                    seq = int(getattr(pkt[IP], "id", 0) or 0)
                frag = Fragment(seq=seq, payload=payload, timestamp=now)
                self.process_fragment(key, "ICMP", frag, ip, mac, complete=False)
            elif TCP in pkt and pkt[TCP].dport == 80:
                payload = bytes(pkt[TCP].payload)
                if not payload:
                    return
                key = (ip, int(pkt[TCP].sport), pkt[IP].dst, 80, "TCP")
                flags = str(pkt[TCP].flags)
                frag = Fragment(seq=int(pkt[TCP].seq), payload=payload, timestamp=now, ack=int(pkt[TCP].ack), flags=flags)
                complete = "F" in flags or "P" in flags or payload.endswith(b"\n")
                result = self.process_fragment(key, "HTTP", frag, ip, mac, complete=complete, dst_port=80)
                if result:
                    self.print_result(result)

        # The exact BPF expressions required by the PDF.
        bpf = "icmp or (tcp and dst port 80)"
        print(f"[AEMF] Live capture on {iface or 'default interface'} with BPF: {bpf}")
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(iface=iface, filter=bpf, prn=handle, store=False, stop_filter=lambda _: self.stop_event.is_set()),
            daemon=True,
        )
        self.sniff_thread.start()

    @staticmethod
    def print_result(result):
        d = result["detection"]
        print(f"[DETECTION] malicious={d.malicious} type={d.attack_type} confidence={d.confidence}")
        print(f"  entropy={d.entropy:.3f} layers={result['layers']}")
        print(f"  reason={d.reason}")
        print(f"  decoded={d.decoded_payload!r}")
        print(f"  blocked={result.get('blocked')}")
