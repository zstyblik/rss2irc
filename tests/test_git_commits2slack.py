#!/usr/bin/env python3
"""Unit tests for git_commits2slack.py."""
import io
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch

import pytest

import git_commits2slack  # noqa:I100,I202


@pytest.fixture
def fixture_git_dir():
    """Create tmpdir and return its file name."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    # Cleanup
    try:
        os.rmdir(tmpdir)
    except FileNotFoundError:
        pass


@patch('subprocess.Popen')
def test_git_branch(mock_popen):
    """Test git_branch()."""
    expected_popen_args = ['git', 'branch', '--no-color']
    expected_branch = '2to3'
    expected_git_clone_dir = '/no/dir'
    mock_output = [
        '* 2to3',
        '  master',
    ]
    # Setup mocked subprocess.Popen
    mock_popen.return_value.communicate.return_value = (
        '\n'.join(mock_output).encode('utf-8'), ''.encode('utf-8'),
    )
    mock_popen.return_value.returncode = 0

    branch = git_commits2slack.git_branch(expected_git_clone_dir)

    mock_popen.assert_called_with(
        expected_popen_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=expected_git_clone_dir,
    )
    mock_popen.return_value.communicate.assert_called_with()

    assert branch == expected_branch


@patch('subprocess.Popen')
def test_git_clone(mock_popen):
    """Test git_clone()."""
    expected_git_url = 'ssh://git@git.example.com:test.git'
    expected_git_clone_dir = '/no/dir'
    expected_popen_args = [
        'git',
        'clone',
        expected_git_url,
        expected_git_clone_dir,
    ]
    # Setup mocked subprocess.Popen
    mock_popen.return_value.communicate.return_value = (
        ''.encode('utf-8'), ''.encode('utf-8'),
    )
    mock_popen.return_value.returncode = 0

    git_commits2slack.git_clone(expected_git_clone_dir, expected_git_url)

    mock_popen.assert_called_with(
        expected_popen_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    mock_popen.return_value.communicate.assert_called_with()


@patch('subprocess.Popen')
def test_git_pull(mock_popen):
    """Test git_pull()."""
    expected_git_clone_dir = '/no/dir'
    expected_popen_args = [
        'git',
        'pull',
    ]
    mock_output = [
        'remote: Enumerating objects: 7, done.',
        'remote: Counting objects: 100% (7/7), done.',
        'remote: Compressing objects: 100% (4/4), done.',
        'remote: Total 4 (delta 3), reused 0 (delta 0), pack-reused 0',
        'Unpacking objects: 100% (4/4), done.',
        'Updating 85736f4..b183857',
    ]
    # Setup mocked subprocess.Popen
    mock_popen.return_value.communicate.return_value = (
        '\n'.join(mock_output).encode('utf-8'), ''.encode('utf-8'),
    )
    mock_popen.return_value.returncode = 0

    retval = git_commits2slack.git_pull(expected_git_clone_dir)

    mock_popen.assert_called_with(
        expected_popen_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=expected_git_clone_dir,
    )
    mock_popen.return_value.communicate.assert_called_with()

    assert retval == '85736f4..b183857'


@patch('subprocess.Popen')
def test_git_show(mock_popen):
    """Test git_show()."""
    expected_git_clone_dir = '/no/dir'
    expected_git_ref = '85736f4..b183857'
    expected_popen_args = [
        'git',
        'show',
        '--pretty=oneline',
        '-s',
        expected_git_ref,
    ]
    expected_output = [
        [
            '5d5b76da52ce3ab5be87f566e8ab117856e7275e',
            (
                '(HEAD -> 2to3, origin/2to3) '
                'Add end-to-end test for phpbb2slack.py'
            ),
        ],
    ]
    mock_output = [
        (
            '5d5b76da52ce3ab5be87f566e8ab117856e7275e '
            '(HEAD -> 2to3, origin/2to3) '
            'Add end-to-end test for phpbb2slack.py'
        ),
    ]
    # Setup mocked subprocess.Popen
    mock_popen.return_value.communicate.return_value = (
        '\n'.join(mock_output).encode('utf-8'), ''.encode('utf-8'),
    )
    mock_popen.return_value.returncode = 0

    retval = git_commits2slack.git_show(
        expected_git_clone_dir, expected_git_ref
    )

    mock_popen.assert_called_with(
        expected_popen_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=expected_git_clone_dir,
    )
    mock_popen.return_value.communicate.assert_called_with()

    assert retval == expected_output


@patch('git_commits2slack.git_branch')
@patch('git_commits2slack.git_pull')
@patch('git_commits2slack.git_show')
def test_main_ideal(
        mock_show, mock_pull, mock_branch,
        monkeypatch, fixture_http_server, fixture_git_dir,
):
    """End-to-end test - ideal environment."""
    git_ref = '85736f4..b183857'
    mock_branch.return_value = 'master'
    mock_pull.return_value = git_ref
    mock_show.return_value = [
        [
            '5d5b76da52ce3ab5be87f566e8ab117856e7275e',
            (
                '(HEAD -> 2to3, origin/2to3) '
                'Add end-to-end test for phpbb2slack.py'
            ),
        ],
    ]
    # Mock/set SLACK_TOKEN
    monkeypatch.setenv('SLACK_TOKEN', 'test')
    # Mock Slack HTTP request
    fixture_http_server.serve_content(
        '{"ok": "true", "error": ""}', 200,
        {'Content-Type': 'application/json'},
    )
    exception = None
    args = [
        './git_commits2slack.py',
        '--git-clone-dir',
        fixture_git_dir,
        '--git-repository',
        'test',
        '--git-web',
        'http://example.com',
        '--slack-base-url',
        fixture_http_server.url,
        '--slack-channel',
        'test',
        '--slack-timeout',
        '10',
        '-v',
    ]

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, 'argv', args):
        try:
            git_commits2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit
        finally:
            sys.stdout = saved_stdout

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 0
    assert out.getvalue().strip() == ''
    # Check mock calls
    mock_branch.assert_called_with(fixture_git_dir)
    mock_pull.assert_called_with(fixture_git_dir)
    mock_show.assert_called_with(fixture_git_dir, git_ref)
    # Check HTTP Slack
    # Note: this is just a shallow check, but it's better than nothing.
    assert len(fixture_http_server.requests) == 1
