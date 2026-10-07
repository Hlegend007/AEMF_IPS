"""ICMP payload reassembly."""

from aemf.reassembler import reassemble


def reassemble_icmp(fragments):
    return reassemble(fragments)


__all__ = ["reassemble_icmp"]