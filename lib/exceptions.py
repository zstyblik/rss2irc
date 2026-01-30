#!/usr/bin/env python3
"""Exceptions for RSS2IRC."""


class RSS2IRCBaseException(Exception):
    """RSS2IRC base exception."""


class CacheReadError(RSS2IRCBaseException):
    """Raised when an error occurs while reading the cache file."""


class CacheWriteError(RSS2IRCBaseException):
    """Raised when an error occurs while writing the cache file."""


class EmptyResponseError(RSS2IRCBaseException):
    """Raised when an empty HTTP response has been received."""


class NoNewsError(RSS2IRCBaseException):
    """Raised when RSS has no news."""


class NotModifiedError(RSS2IRCBaseException):
    """Raised when HTTP content has not changed."""


class SlackTokenError(RSS2IRCBaseException):
    """Raised when SLACK_TOKEN env variable is not set or empty."""
