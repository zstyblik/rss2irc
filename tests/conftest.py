#!/usr/bin/env python3
"""Fixtures shared by pytest."""
import os
import tempfile

import pytest
import requests_mock
from pytest_localserver.http import ContentServer
from werkzeug.wrappers import Request


class MyContentServer(ContentServer):
    """Wrapper around `pytest_localserver.http.ContentServer`.

    It actually stores intercepted requests and data. It's not the best
    implementation, but it gets job done - for now.
    """

    def __init__(self, capture_requests=False, *args, **kwargs):
        """Init."""
        self.captured_requests = []
        self.capture_requests = False
        super(MyContentServer, self).__init__(*args, **kwargs)

    def __call__(self, environ, start_response):
        """Intercept HTTP request and store it, if desired."""
        if self.capture_requests:
            request = Request(environ)
            self.captured_requests.append((request.method, request.get_data()))

        return super(MyContentServer, self).__call__(environ, start_response)


@pytest.fixture
def fixture_cache_file():
    """Create tmpfile and return its file name."""
    file_desc, fname = tempfile.mkstemp()
    os.fdopen(file_desc).close()
    yield fname
    # Cleanup
    try:
        os.unlink(fname)
    except FileNotFoundError:
        pass


@pytest.fixture
def fixture_http_server():
    """Return instance of HTTP server for testing."""
    server = MyContentServer()
    server.start()
    yield server

    server.stop()


@pytest.fixture
def fixture_mock_requests():
    """Return started up requests_mock and cleanup on teardown."""
    mock_requests = requests_mock.Mocker(real_http=True)
    mock_requests.start()
    yield mock_requests

    mock_requests.stop()


@pytest.fixture
def fixture_output_file():
    """Create tmpfile and return its file name."""
    file_desc, fname = tempfile.mkstemp()
    os.fdopen(file_desc).close()
    yield fname
    # Cleanup
    try:
        os.unlink(fname)
    except FileNotFoundError:
        pass
