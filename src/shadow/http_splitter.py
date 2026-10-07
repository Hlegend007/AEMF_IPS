"""HTTP splitter simulation facade."""

from shadow.attacks import HTTP_PAYLOAD, Shadow


def build_http_splitter(**kwargs):
    return Shadow().build("http", **kwargs)


__all__ = ["HTTP_PAYLOAD", "build_http_splitter"]