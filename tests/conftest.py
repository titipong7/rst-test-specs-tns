"""
tests/conftest.py – test-level shared fixtures.

This file intentionally imports nothing at module level so that tests can be
collected even when the optional dependencies (e.g. lxml, OpenSSL) are absent.
"""
