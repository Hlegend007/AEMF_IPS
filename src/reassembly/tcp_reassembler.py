"""TCP payload reassembly."""

from aegis.reassembler import reassemble


def reassemble_tcp(fragments):
    return reassemble(fragments)


__all__ = ["reassemble_tcp"]