"""Shared, dependency-free building blocks used by every other layer.

Nothing here does network I/O against the lab; these are the contracts the rest
of the package agrees on — the node/edge schema, the one MAC canonicalizer, and
the env-var / HTTP conventions.
"""
