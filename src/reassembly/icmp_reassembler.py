"""ICMP payload reassembly."""

from aegis.reassembler import reassemble


def reassemble_icmp(fragments):
    return reassemble(fragments)


__all__ = ["reassemble_icmp"]