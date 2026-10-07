import argparse
import os
import platform
import sys
import time

from config import SETTINGS, BLOCK_LOG, SIGNATURES_FILE
from aemf.logger import BlockLogger
from aemf.models import Fragment
from aemf.monitor import AEMFMonitor
from aemf.performance import run_processing_benchmark
from aemf.signatures import SignatureDB
from shadow.attacks import Shadow

def make_monitor(simulation=True):
    return AEMFMonitor(
        SETTINGS,
        SignatureDB(SIGNATURES_FILE),
        BlockLogger(BLOCK_LOG),
        simulation=simulation,
    )

def simulate(attack):
    monitor = make_monitor(simulation=True)
    shadow = Shadow()
    print("[SIMULATION] No real packets or firewall rules are used.")
    plans = []
    if attack in ("icmp", "both"):
        plans.append(shadow.build("icmp", layers=["base64"], fragment_size=4, out_of_order=True))
    if attack in ("http", "both"):
        plans.append(shadow.build("http", layers=["url"], fragment_size=2, out_of_order=True))
    for plan in plans:
        protocol = plan["protocol"]
        key = ("192.168.56.10", 1234, "192.168.56.20", 80, "TCP") if protocol == "HTTP" else ("192.168.56.10", 99)
        print(f"\n[SHADOW] {protocol} original: {plan['original']}")
        print(f"[SHADOW] encoding layers: base64/url; fragments={len(plan['fragments'])}")
        # The simulator uses a fixed, lab-only MAC identity.
        for idx, (seq, payload) in enumerate(plan["fragments"]):
            frag = Fragment(seq=seq, payload=payload, timestamp=time.time())
            complete = idx == len(plan["fragments"]) - 1
            result = monitor.process_fragment(
                key, protocol, frag,
                ip="192.168.56.10",
                mac="02:00:00:00:00:02",
                complete=complete,
                dst_port=80 if protocol == "HTTP" else None,
            )
            if result:
                monitor.print_result(result)
    print(f"\n[LOG] {BLOCK_LOG}")
    print("[SIMULATION] Completed.")

def live(args):
    if platform.system().lower() != "linux":
        raise SystemExit("Live capture/prevention requires Linux. On Windows use: python main.py simulate --attack both")
    monitor = make_monitor(simulation=args.simulate_firewall)
    monitor.start_live(args.interface)
    print("[AEMF] Running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\n[AEMF] stopped.")

def benchmark(packets):
    monitor = make_monitor(simulation=True)
    result = run_processing_benchmark(monitor, packets)
    print("[BENCHMARK] Synthetic processing test")
    print(f"Packets: {result['packets']}")
    print(f"Elapsed: {result['elapsed_seconds']:.3f}s")
    print(f"Rate: {result['packets_per_second']:.1f} packets/sec")
    if result["resource_metrics_available"]:
        print(f"Process CPU sample: {result['cpu_percent']:.1f}%")
        print(f"Process RSS: {result['memory_mb']:.1f} MB")
    else:
        print("Process CPU/RSS: unavailable (install psutil)")
    print(f"Target rate >1000 packets/sec: {'PASS' if result['packets_per_second'] > 1000 else 'FAIL'}")
    if result["resource_metrics_available"]:
        print(f"Target memory < 100 MB: {'PASS' if result['memory_mb'] < 100 else 'FAIL'}")
    else:
        print("Target memory < 100 MB: NOT MEASURED")

def unblock(args):
    monitor = make_monitor(simulation=platform.system().lower() != "linux")
    try:
        monitor.prevention.unblock(args.mac, args.admin, args.reason)
    except Exception as exc:
        raise SystemExit(f"Unblock failed: {exc}")
    print(f"UNBLOCK recorded for {args.mac}")

def status():
    print("AEMF-IPS / AEMF IPS")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Simulation available: yes")
    print(f"Live Linux capture: {'yes' if platform.system().lower() == 'linux' else 'no'}")
    print(f"Signature database: {SIGNATURES_FILE}")
    print(f"Block log: {BLOCK_LOG}")
    print(f"Entropy threshold: {SETTINGS.entropy_threshold}")
    print(f"ICMP entropy threshold: {SETTINGS.icmp_entropy_threshold}")
    print(f"Normalization iterations: {SETTINGS.normalization_max_iterations}")
    print(f"Session TTL: {SETTINGS.session_ttl}s")
    print(f"Block duration: {SETTINGS.block_duration}s")

def _clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def _pause():
    input("\nPress ENTER to return to the main menu...")

def _box(title, lines, width=72):
    print("+" + "-" * width + "+")
    print("| " + title.center(width - 2) + " |")
    print("+" + "-" * width + "+")
    for line in lines:
        print("| " + str(line)[:width - 2].ljust(width - 2) + " |")
    print("+" + "-" * width + "+")

def _startup_screen():
    _clear_screen()
    _box("AEMF IPS", [
        "Intrusion Prevention System  v1.0.0",
        "Detecting ICMP Tunneling and HTTP Splitter Attacks",
        "",
        "[OK] BPF filter: icmp or (tcp and dst port 80)",
        "[OK] State table: active session tracking",
        f"[OK] Signature database: {SIGNATURES_FILE}",
        f"[OK] Entropy threshold: {SETTINGS.entropy_threshold}",
        "[OK] MAC blocker: iptables + ebtables ready on Linux",
        f"[OK] Logger: {BLOCK_LOG}",
    ])
    _pause()

def _view_sessions(monitor):
    _clear_screen()
    sessions = monitor.state.snapshot()
    lines = [f"Active sessions: {len(sessions)}", ""]
    if sessions:
        lines.extend(f"{key} | fragments: {count}" for key, count in sessions.items())
    else:
        lines.append("No active sessions.")
    _box("AEMF IPS - ACTIVE SESSIONS", lines)
    _pause()

def _read_block_events():
    if not BLOCK_LOG.exists():
        return []
    events = []
    for line in BLOCK_LOG.read_text(encoding="utf-8").splitlines():
        fields = line.split("|")
        if len(fields) >= 5:
            events.append(fields)
    return events

def _view_blocked(monitor):
    _clear_screen()
    active = list(monitor.prevention.blocks)
    events = _read_block_events()
    lines = ["No in-memory blocks." if not active else "Active in-memory blocks:"]
    lines.extend(f"{index}. {mac}" for index, mac in enumerate(active, 1))
    if events:
        lines.extend(["", "Recent block events:"])
        for fields in events[-10:]:
            lines.append(f"{fields[1]} | {fields[2]} | {fields[3]}")
    _box("AEMF IPS - BLOCKED DEVICES", lines)
    _pause()

def _view_log():
    _clear_screen()
    events = _read_block_events()
    lines = []
    for fields in events[-12:]:
        if fields[1] == "BLOCK" and len(fields) >= 9:
            lines.extend([
                f"{fields[0]}  BLOCK  {fields[2]}",
                f"  IP: {fields[3]}  Type: {fields[4]}  Confidence: {fields[7]}",
                f"  Decoded: {fields[6]}",
                f"  Reason: {fields[8]}",
                "-" * 70,
            ])
        elif fields[1] == "UNBLOCK":
            lines.append(f"{fields[0]}  UNBLOCK  {fields[2]}  {fields[4]}")
    _box("AEMF IPS - BLOCK LOG", lines or ["No block events recorded."])
    _pause()

def _unblock_from_menu(monitor):
    _clear_screen()
    mac = input("MAC address to unblock: ").strip()
    if not mac:
        return
    admin = input("Administrator [administrator]: ").strip() or "administrator"
    reason = input("Reason [Manual unblock]: ").strip() or "Manual unblock"
    try:
        monitor.prevention.unblock(mac, admin, reason)
        print(f"Unblock recorded for {mac}.")
    except Exception as exc:
        print(f"Unblock failed: {exc}")
    _pause()

def _settings_screen():
    _clear_screen()
    _box("AEMF IPS - SETTINGS", [
        f"HTTP entropy threshold: {SETTINGS.entropy_threshold}",
        f"ICMP entropy threshold: {SETTINGS.icmp_entropy_threshold}",
        f"Session TTL: {SETTINGS.session_ttl}s",
        f"Garbage collection interval: {SETTINGS.gc_interval}s",
        f"Normalization iterations: {SETTINGS.normalization_max_iterations}",
        f"Normalization timeout: {SETTINGS.normalization_timeout}s",
        f"Block duration: {SETTINGS.block_duration}s",
    ])
    _pause()

def _start_live_from_menu():
    if platform.system().lower() != "linux":
        print("Live capture requires Linux.")
        _pause()
        return
    interface = input("Interface: ").strip() or None
    firewall = input("Simulate firewall changes? [Y/n]: ").strip().lower()
    monitor = make_monitor(simulation=firewall != "n")
    try:
        monitor.start_live(interface)
        input("\nAEMF is monitoring. Press ENTER to stop live capture...")
    except Exception as exc:
        print(f"Live capture failed: {exc}")
        _pause()
    finally:
        monitor.stop()

def menu():
    monitor = make_monitor(simulation=True)
    _startup_screen()
    while True:
        _clear_screen()
        _box("AEMF IPS - MAIN MENU", [
            "[1]  Start live monitoring",
            "[2]  View active sessions",
            "[3]  View blocked MAC addresses",
            "[4]  View block log",
            "[5]  Unblock a MAC address",
            "[6]  Run test cases (demo mode)",
            "[7]  Settings",
            "[8]  About",
            "[9]  Exit",
        ])
        choice = input("\nSelect option [1-9]: ").strip()
        if choice == "1":
            _start_live_from_menu()
        elif choice == "2":
            _view_sessions(monitor)
        elif choice == "3":
            _view_blocked(monitor)
        elif choice == "4":
            _view_log()
        elif choice == "5":
            _unblock_from_menu(monitor)
        elif choice == "6":
            _clear_screen()
            simulate("both")
            _pause()
        elif choice == "7":
            _settings_screen()
        elif choice == "8":
            _clear_screen()
            _box("ABOUT AEMF IPS", [
                "A modular academic intrusion prevention prototype.",
                "Packet capture, session tracking, normalization, detection,",
                "MAC prevention, evidence logging, and safe simulation.",
            ])
            _pause()
        elif choice == "9":
            print("Exiting AEMF IPS.")
            return
        else:
            print("Invalid option.")

def main():
    parser = argparse.ArgumentParser(prog="aemf-ips", description="AEMF-IPS / AEMF IPS academic prototype")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("simulate", help="Run the complete offline Shadow/AEMF demo")
    p.add_argument("--attack", choices=["icmp", "http", "both"], default="both")
    p.set_defaults(func=lambda a: simulate(a.attack))

    p = sub.add_parser("live", help="Run live Linux packet capture with BPF")
    p.add_argument("--interface", default=None)
    p.add_argument("--simulate-firewall", action="store_true", help="Log blocks without changing firewall rules")
    p.set_defaults(func=live)

    p = sub.add_parser("benchmark", help="Run a synthetic performance benchmark")
    p.add_argument("--packets", type=int, default=10000)
    p.set_defaults(func=lambda a: benchmark(a.packets))

    p = sub.add_parser("unblock", help="Remove a MAC block")
    p.add_argument("mac")
    p.add_argument("--admin", default=os.getenv("USERNAME", "administrator"))
    p.add_argument("--reason", default="Manual unblock")
    p.set_defaults(func=unblock)

    p = sub.add_parser("status", help="Show configuration")
    p.set_defaults(func=lambda _: status())

    p = sub.add_parser("menu", help="Open the interactive options menu")
    p.set_defaults(func=lambda _: menu())
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
