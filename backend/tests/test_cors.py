"""
DriftGuard — CORS origin normalization tests.

Run: pytest backend/tests/test_cors.py -v
"""

from backend.api.main import normalize_origin


def test_bare_hostname_gets_https_scheme():
    assert normalize_origin("driftguard-frontend.onrender.com") == "https://driftguard-frontend.onrender.com"


def test_already_schemed_origin_is_unchanged():
    assert normalize_origin("https://example.com") == "https://example.com"
    assert normalize_origin("http://localhost:5173") == "http://localhost:5173"


def test_wildcard_is_unchanged():
    assert normalize_origin("*") == "*"


def test_whitespace_is_stripped_before_check():
    assert normalize_origin("  driftguard-frontend.onrender.com  ") == "https://driftguard-frontend.onrender.com"


def test_empty_string_is_unchanged():
    assert normalize_origin("") == ""
