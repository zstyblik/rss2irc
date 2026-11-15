#!/usr/bin/env python3
"""Utility functions used in rss2irc."""
import logging
from typing import Dict

import requests

from .config_options import HTTP_TIMEOUT
from .exceptions import EmptyResponseError
from .exceptions import NotModifiedError

module_logger = logging.getLogger("rss2irc.lib.utils")


def calc_log_level(count: int) -> int:
    """Return logging log level as int based on count."""
    log_level = 40 - max(count, 0) * 10
    log_level = max(log_level, 10)
    return log_level


def escalate_retcode(new_rc: int, old_rc: int) -> int:
    """Return retcode which is bigger."""
    retcode = old_rc
    if new_rc > old_rc:
        retcode = new_rc

    return retcode


def get_rss(
    url: str,
    timeout: int = HTTP_TIMEOUT,
    extra_headers: Dict = None,
) -> requests.models.Response:
    """Return body of given URL as a string.

    :raises EmptyResponseError: raised when HTTP rsp body is empty
    :raises NotModifiedError: raised when HTTP Status Code is 304
    :raises requests.exceptions.BaseHTTPError: raised when HTTP error occurs
    """
    user_agent = "rss2irc-script"
    headers = {
        "User-Agent": user_agent,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ),
    }
    if extra_headers:
        for key, value in extra_headers.items():
            headers[key] = value

    module_logger.debug("Make request at URL '%s'.", url)
    rsp = requests.get(url, timeout=timeout, headers=headers)
    module_logger.debug("Got HTTP Status Code '%i'.", rsp.status_code)
    rsp.raise_for_status()

    if rsp.status_code == 304:
        raise NotModifiedError

    if not rsp.text:
        raise EmptyResponseError

    return rsp


def mask_retcode(retcode: int, mask: bool) -> int:
    """Determine whether or not to mask error return code, if so mask it."""
    if mask:
        retcode = 0

    return retcode
