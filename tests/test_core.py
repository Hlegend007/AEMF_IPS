import time
from dataclasses import replace
import json
import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import SETTINGS, SIGNATURES_FILE
from aemf.entropy import shannon_entropy
from aemf.models import Fragment
from aemf.normalizer import RecursiveNormalizer
from aemf.reassembler import reassemble
from aemf.signatures import SignatureDB
from aemf.monitor import AEMFMonitor
from aemf.logger import BlockLogger
from shadow.mutator import encode_layers
from shadow.attacks import HTTP_DESYNC_PAYLOADS, ICMP_TUNNEL_PAYLOADS, Shadow

def test_entropy():
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abcdef") > 2.0

def test_recursive_decode():
    raw = "ncat"
    encoded = encode_layers(raw, ["base64", "hex", "url"])
    decoded, layers, warnings = RecursiveNormalizer().normalize(encoded)
    assert decoded == raw
    assert len(layers) >= 3
    assert not warnings

def test_overlap_reassembly_later_wins():
    out = reassemble([
        Fragment(0, b"abcd", time.time()),
        Fragment(2, b"XY", time.time()),
    ])
    assert out == b"abXY"

def test_icmp_detection_and_block(tmp_path):
    log = BlockLogger(tmp_path/"block.log")
    monitor = AEMFMonitor(SETTINGS, SignatureDB(SIGNATURES_FILE), log, simulation=True)
    payload = encode_layers("ncat -e /bin/sh", ["base64"])
    chunks = [payload[i:i+4].encode() for i in range(0, len(payload), 4)]
    result = None
    for i, chunk in enumerate(chunks):
        result = monitor.process_fragment(
            ("1.1.1.1", 99), "ICMP",
            Fragment(i*4, chunk, time.time()),
            "1.1.1.1", "02:00:00:00:00:02",
            complete=(i == len(chunks)-1)
        )
    assert result["detection"].malicious
    assert result["detection"].attack_type == "ICMP_TUNNEL"
    assert result["blocked"]
    assert "BLOCK" in (tmp_path/"block.log").read_text()

def test_http_desync_variants_match_signatures():
    db = SignatureDB(SIGNATURES_FILE)
    expected = {
        "cl_te": "http_cl_te",
        "te_cl": "http_te_cl",
        "te_te": "http_te_te_obfuscation",
        "crlf_injection": "http_crlf_injection",
        "dual_content_length": "http_dual_content_length",
        "expect_continue": "http_expect_continue",
    }
    for variant, signature in expected.items():
        hits = db.match(HTTP_DESYNC_PAYLOADS[variant], "HTTP")
        assert signature in {hit.name for hit in hits}

def test_http_desync_builder():
    plan = Shadow().build("cl_te", fragment_size=8)
    assert plan["protocol"] == "HTTP"
    assert b"Transfer-Encoding" in b"".join(payload for _, payload in plan["fragments"])
    assert Shadow().build("pause")["delay"] == 0.5

def test_icmp_tunnel_variants_match_signatures():
    db = SignatureDB(SIGNATURES_FILE)
    for variant, (_, _, payload) in ICMP_TUNNEL_PAYLOADS.items():
        if variant == "large_payload":
            continue
        assert db.match(payload, "ICMP")

def test_icmp_typed_builder():
    plan = Shadow().build("timestamp", fragment_size=8)
    assert plan["protocol"] == "ICMP"
    assert plan["icmp_type"] == 13

def test_icmp_live_plan_has_completion_payload():
    plan = Shadow().build("echo_loki", fragment_size=8)
    assert plan["icmp_type"] == 8
    assert plan["fragments"]

def test_stale_icmp_session_is_analyzed(tmp_path):
    settings = replace(SETTINGS, session_ttl=0.01, gc_interval=0.01)
    log = BlockLogger(tmp_path / "block.log")
    monitor = AEMFMonitor(settings, SignatureDB(SIGNATURES_FILE), log, simulation=True)
    monitor.process_fragment(
        ("1.1.1.1", 99), "ICMP",
        Fragment(0, b"ncat -e /bin/sh", time.time()),
        "1.1.1.1", "02:00:00:00:00:02",
    )
    monitor.state.sessions[("1.1.1.1", 99)].last_seen = time.time() - 1
    monitor.start_gc()
    time.sleep(0.05)
    monitor.stop()
    assert not monitor.state.sessions
    assert monitor.prevention.is_blocked("02:00:00:00:00:02")

def test_invalid_signature_pattern_fails_at_load(tmp_path):
    path = tmp_path / "signatures.json"
    path.write_text(json.dumps([{
        "name": "broken",
        "pattern": "(",
        "description": "invalid",
        "severity": "HIGH",
        "protocol": "BOTH",
    }]), encoding="utf-8")
    with pytest.raises(ValueError, match="broken"):
        SignatureDB(path)
