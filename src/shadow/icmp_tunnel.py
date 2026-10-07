"""ICMP tunnel simulation facade."""

from shadow.attacks import ICMP_PAYLOAD, Shadow


def build_icmp_tunnel(**kwargs):
    return Shadow().build("icmp", **kwargs)


__all__ = ["ICMP_PAYLOAD", "build_icmp_tunnel"]