# AEMF-IPS / AEMF IPS Prototype

## Modes

- **Simulation mode (Windows/Linux):** exercises Shadow -> AEMF end-to-end without raw sockets or firewall changes.
- **Live defender mode (Linux):** Scapy sniffer with the PDF's BPF filters and optional iptables/ebtables prevention.
- **Live Shadow sender (Linux, isolated lab only):** sends benign test fragments containing the PDF's sample attack strings. It does not execute commands.

The root-level `aemf/` and `shadow/` packages are the canonical implementation. The `src/` tree is retained as a legacy reference and is not used by the primary entry points.

Linux is the primary platform in the PDF because packet capture and iptables/ebtables require Linux privileges. Windows is supported through simulation mode, matching the PDF's "Windows (optional)" portability requirement.

## Quick start

```powershell
py -3.10 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python main.py simulate --attack icmp
python main.py simulate --attack http
python main.py simulate --attack both
python main.py status
python main.py benchmark --packets 10000
python main.py unblock 02:00:00:00:00:02 --reason "False positive recovery demo" --admin "student"
```

For development and tests, install the optional test dependency:

```powershell
python -m pip install -e ".[test]"
```

For Linux live capture, run the defender with appropriate privileges and an isolated host-only VM network.

## Important safety note

Use live packet generation and firewall blocking only on the isolated Host-Only Adapter lab described by the project. The prototype never executes the payload strings.
