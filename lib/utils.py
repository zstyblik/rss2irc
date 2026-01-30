#!/usr/bin/env python3
"""Utility functions used in rss2irc."""


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


def mask_retcode(retcode: int, mask: bool) -> int:
    """Determine whether or not to mask error return code, if so mask it."""
    if mask:
        retcode = 0

    return retcode
