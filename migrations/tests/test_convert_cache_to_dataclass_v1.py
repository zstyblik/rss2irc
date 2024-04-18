#!/usr/bin/env python3
"""Unit tests for convert_cache_to_dataclass_v1.py."""
import logging
import os
import pickle
import subprocess
import tempfile

import pytest

import rss2irc  # noqa:I202

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture
def fixture_bak_cleanup():
    """Cleanup bak file which is created during migration."""
    bak_fnames = []

    def _fixture_back_cleanup(bak_fname):
        bak_fnames.append(bak_fname)
        return bak_fname

    yield _fixture_back_cleanup

    for bak_fname in bak_fnames:
        print("teardown of '{}'".format(bak_fname))
        try:
            os.unlink(bak_fname)
        except FileNotFoundError:
            pass


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


def test_migration(fixture_cache_file, fixture_bak_cleanup):
    """Test migration under ideal conditions."""
    bak_file = "{}.bak".format(fixture_cache_file)
    _ = fixture_bak_cleanup(bak_file)

    test_data = {
        "test1": 1234,
        "test2": 0,
    }
    with open(fixture_cache_file, "wb") as fhandle:
        pickle.dump(test_data, fhandle, pickle.HIGHEST_PROTOCOL)

    expected_cache = rss2irc.CachedData(
        items={
            "test1": 1234,
            "test2": 0,
        }
    )

    cmd_migrate = [
        os.path.join(SCRIPT_PATH, "..", "convert_cache_to_dataclass_v1.py"),
        "--cache",
        fixture_cache_file,
    ]
    proc_migrate = subprocess.Popen(
        cmd_migrate,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc_migrate.communicate()
    print("migrate-cache STDOUT: {}".format(out))
    print("migrate-cache STDERR: {}".format(err))
    assert proc_migrate.returncode == 0

    assert os.path.exists(bak_file) is True

    cmd_read = [
        os.path.join(SCRIPT_PATH, "files", "read_migrated_cache.py"),
        "--cache",
        fixture_cache_file,
    ]
    proc_read_env = os.environ.copy()
    # An ugly hack
    proc_read_env["PYTHONPATH"] = os.path.join(SCRIPT_PATH, "..", "..")

    proc_read = subprocess.Popen(
        cmd_read,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=proc_read_env,
    )
    out, err = proc_read.communicate()
    print("read-migrated-cache STDOUT: {}".format(out))
    print("read-migrated-cache STDERR: {}".format(err))
    assert "Traceback" not in err.decode("utf-8")
    assert proc_read.returncode == 0

    logger = logging.getLogger("pytest")
    migrated_cache = rss2irc.read_cache(logger, fixture_cache_file)
    assert migrated_cache == expected_cache
