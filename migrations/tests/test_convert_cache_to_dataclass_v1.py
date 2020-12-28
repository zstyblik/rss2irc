#!/usr/bin/env python3
"""Unit tests for convert_cache_to_dataclass_v1.py."""
import io
import os
import pickle
import sys
import tempfile
from unittest.mock import patch

import pytest

import migrations.convert_cache_to_dataclass_v1 as migration  # noqa:I202


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
        os.remove(bak_fname)


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
    bak_file = '{}.bak'.format(fixture_cache_file)
    _ = fixture_bak_cleanup(bak_file)
    expected_cache = migration.CachedData(
        items={
            'test1': 1234,
            'test2': 0,
        }
    )

    test_data = {
        'test1': 1234,
        'test2': 0,
    }
    with open(fixture_cache_file, 'wb') as fhandle:
        pickle.dump(test_data, fhandle, pickle.HIGHEST_PROTOCOL)

    exception = None
    args = [
        './convert_cache_to_dataclass_v1.py',
        '--cache',
        fixture_cache_file,
    ]

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, 'argv', args):
        try:
            migration.main()
        except Exception as exc:
            exception = exc
        finally:
            sys.stdout = saved_stdout

    assert exception is None
    assert os.path.exists(bak_file) is True

    with open(fixture_cache_file, 'rb') as fhandle:
        migrated_cache = pickle.load(fhandle)
    assert migrated_cache == expected_cache
