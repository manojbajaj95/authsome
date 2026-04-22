import http.server

import pytest


@pytest.fixture(autouse=True)
def allow_http_server_reuse():
    """Workaround for 'Address already in use' errors by enabling allow_reuse_address globally for tests."""
    original_val = http.server.HTTPServer.allow_reuse_address
    http.server.HTTPServer.allow_reuse_address = True
    yield
    http.server.HTTPServer.allow_reuse_address = original_val
