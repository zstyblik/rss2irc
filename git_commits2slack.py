#!/usr/bin/env python2
"""2017/Nov/17 @ Zdenek Styblik <stybla@turnovfree.net>
Desc: Unfortunately, slack integration doesn't allow you to track github
repositories which aren't yours. Let's work-around it.
"""
import argparse
import logging
import os
import subprocess
import sys

from slackclient import SlackClient
import rss2irc
import rss2slack


def git_branch(git_clone_dir):
    """Run % git branch; and return name of current branch.

    :type git_clone_dir: str

    :rtype: str
    """
    git_branch_proc = subprocess.Popen(
        ['git', 'branch', '--no-color'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=git_clone_dir,
    )
    out, err = git_branch_proc.communicate()
    retcode = git_branch_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            'git branch has returned {:d}, err: {}'.format(retcode, err)
        )

    branch_name = ''
    for line in out.splitlines():
        if line.startswith('*'):
            branch_name = line.strip().split(' ', 1)[1]
            break

    if not branch_name:
        raise ValueError('Failed to get branch name.')

    return branch_name


def git_clone(git_clone_dir, git_repo):
    """Clone given git repository into given directory.

    :type git_clone_dir: str
    :type git_repo: str
    """
    git_clone_proc = subprocess.Popen(
        ['git', 'clone', git_repo, git_clone_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, err = git_clone_proc.communicate()
    retcode = git_clone_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            'git clone has returned {:d}, err: {}'.format(retcode, err)
        )


def git_pull(git_clone_dir):
    """Run % git pull; and return it's stdout.

    :type git_clone_dir: str
    """
    git_pull_proc = subprocess.Popen(['git', 'pull'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     cwd=git_clone_dir)
    out, err = git_pull_proc.communicate()
    retcode = git_pull_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            'git pull has returned {:d}, err: {}'.format(retcode, err)
        )

    return out


def git_show(git_clone_dir):
    """Run % git show; and return commit hash and title as list of tuples.

    :type git_clone_dir: str

    :rtype: list
    """
    git_show_proc = subprocess.Popen(
        ['git', 'show', '--pretty=oneline', '-s'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=git_clone_dir)
    out, err = git_show_proc.communicate()
    retcode = git_show_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            'git show has returned {:d}, err: {}'.format(retcode, err)
        )

    return parse_commits(out)


def main():
    """Main."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger('git-commits2slack')
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    slack_token = rss2slack.get_slack_token()

    if not os.path.isdir(args.git_clone_dir):
        git_clone(args.git_clone_dir, args.git_repo)

    os.chdir(args.git_clone_dir)
    out = git_pull(args.git_clone_dir)
    if out.startswith('Already up-to-date.'):
        logger.info('No new commits.')
        sys.exit(0)

    commits = git_show(args.git_clone_dir)
    if not commits:
        logger.warning('There should be new commits, but we have none.')
        sys.exit(0)

    repo_name = os.path.basename(args.git_clone_dir)
    branch_name = git_branch(args.git_clone_dir)
    commit_count = len(commits)
    if commit_count > 1:
        suffix = 's'
    else:
        suffix = ''

    messages = [
        '<{}/commit/{}|{}> {}'.format(
            args.git_web, commit[0], commit[0], commit[1]
        )
        for commit in commits
    ]
    heading = '<{}/tree/{}|{}:{}> {:d} commit{}'.format(
        args.git_web, branch_name, repo_name, branch_name, commit_count, suffix
    )
    messages.insert(0, heading)

    slack_client = SlackClient(slack_token)
    rss2slack.post_to_slack(
        logger, '\n'.join(messages), slack_client, args.slack_channel,
        args.slack_timeout
    )


def parse_args():
    """Return parsed CLI args.

    :rtype: `argparse.Namespace`
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--git-clone-dir',
        dest='git_clone_dir', required=True, type=str,
        help='Directory where git repository will be cloned into.'
    )
    parser.add_argument(
        '--git-repository',
        dest='git_repo', required=True, type=str,
        help='git repository to track.'
    )
    parser.add_argument(
        '--git-web',
        dest='git_web', type=str, default='http://localhost',
        help='git web interface, resp. base URL, for given repository.'
    )
    parser.add_argument(
        '--slack-channel',
        dest='slack_channel', type=str, required=True,
        help='Name of slack channel to send formatted news to.'
    )
    parser.add_argument(
        '--slack-timeout',
        dest='slack_timeout', type=int,
        default=rss2irc.HTTP_TIMEOUT,
        help=('slack API Timeout. Defaults to %i seconds.'
              % rss2irc.HTTP_TIMEOUT)
    )
    parser.add_argument(
        '--sleep',
        dest='sleep', type=int, default=2,
        help='Sleep between messages in order to avoid '
             'possible excess flood/API call rate limit.'
    )
    parser.add_argument(
        '-v', '--verbose',
        dest='verbosity', action='store_true', default=False,
        help='Increase logging verbosity.'
    )
    return parser.parse_args()


def parse_commits(output):
    """Return commit hash and title as list of tuples.

    :type output: str
    :param output: Output of % git show; command.

    :rtype: list
    """
    return [
        line.strip().split(' ', 1)
        for line in output.splitlines()
        if line.strip() != ''
    ]


if __name__ == '__main__':
    main()
