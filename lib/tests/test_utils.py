#!/usr/bin/env python3
"""Unit tests for utils.py."""
import pytest

from lib import utils


@pytest.mark.parametrize(
    "new_rc,old_rc,expected",
    [
        (0, 0, 0),
        (0, 1, 1),
        (1, 1, 1),
        (1, 0, 1),
        (2, 1, 2),
        (1, 2, 2),
        (-1, 0, 0),
    ],
)
def test_escalate_retcode(new_rc, old_rc, expected):
    """Test that escalate_retcode() works as expected."""
    result = utils.escalate_retcode(new_rc, old_rc)
    assert result == expected


@pytest.mark.parametrize(
    "retcode,mask,expected",
    [
        (0, False, 0),
        (0, True, 0),
        (1, False, 1),
        (1, True, 0),
        (20, False, 20),
        (20, True, 0),
    ],
)
def test_mask_retcode(retcode, mask, expected):
    """Test that mask_retcode() works as expected."""
    result = utils.mask_retcode(retcode, mask)
    assert result == expected
