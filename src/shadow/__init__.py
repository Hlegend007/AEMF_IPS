"""Controlled attack traffic generators for isolated lab simulation."""

from .icmp_tunnel import ICMP_PAYLOAD, build_icmp_tunnel
from .http_splitter import HTTP_PAYLOAD, build_http_splitter

__all__ = [
    "ICMP_PAYLOAD",
    "HTTP_PAYLOAD",
    "build_icmp_tunnel",
    "build_http_splitter",
]