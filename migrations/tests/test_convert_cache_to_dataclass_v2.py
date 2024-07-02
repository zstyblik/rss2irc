#!/usr/bin/env python3
"""Unit tests for convert_cache_to_dataclass_v2.py."""
import os
import subprocess

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def test_convert_v2_help_arg():
    """Run convert v2 with --help arg.

    As a matter of fact, this is just a dry run to catch import and syntax
    errors. In other words to have at least some "test".
    """
    migration_script_fpath = os.path.join(
        SCRIPT_PATH, "..", "convert_cache_to_dataclass_v2.py"
    )
    migration_proc = subprocess.Popen(
        [migration_script_fpath, "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=SCRIPT_PATH,
    )
    out, err = migration_proc.communicate()
    assert migration_proc.returncode == 0
    assert "usage: convert_cache_to_dataclass_v2.py" in out.decode("utf-8")
    assert err.decode("utf-8") == ""
