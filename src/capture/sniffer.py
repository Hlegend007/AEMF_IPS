"""Packet capture boundary for the Aegis monitor."""

from aegis.monitor import AegisMonitor

BPF_FILTER = "icmp or (tcp and dst port 80)"

__all__ = ["AegisMonitor", "BPF_FILTER"]