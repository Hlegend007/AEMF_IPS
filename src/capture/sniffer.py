"""Packet capture boundary for the AEMF monitor."""

from aemf.monitor import AEMFMonitor

BPF_FILTER = "icmp or (tcp and dst port 80)"

__all__ = ["AEMFMonitor", "BPF_FILTER"]