"""TCP payload reassembly."""

from aemf.reassembler import reassemble


def reassemble_tcp(fragments):
    return reassemble(fragments)


__all__ = ["reassemble_tcp"]