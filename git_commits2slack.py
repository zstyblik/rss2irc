#!/usr/bin/env python3
"""Post new commits in given git repository to Slack.

Unfortunately Slack integration doesn't allow you to track Github repositories
which aren't yours. Let's work-around it.

2017/Nov/17 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import os
import re
import subprocess
import sys
import traceback
from typing import Dict
from typing import List

import rss2irc
import rss2slack

RE_GIT_AUTD = re.compile(r"^Already up-to-date.$")
RE_GIT_UPDATING = re.compile(r"^Updating [a-z0-9]+", re.I)


def format_commit_message(
    git_web_url: str, commit_hash: str, commit_message: str
) -> Dict:
    """Return formatted commit message as Slack's BlockKit section."""
    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "* {:s} | <{:s}/commit/{:s}|{:s}>".format(
                commit_message, git_web_url, commit_hash, commit_hash[0:6]
            ),
        },
    }


def format_heading(
    git_web_url: str, branch_name: str, repo_name: str, commit_count: int
) -> Dict:
    """Return formatted heading as Slack's BlockKit section."""
    if commit_count > 1:
        suffix = "s"
    else:
        suffix = ""

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "<{}/tree/{}|[{}:{}]> {:d} commit{}".format(
                git_web_url,
                branch_name,
                repo_name,
                branch_name,
                commit_count,
                suffix,
            ),
        },
    }


def git_branch(git_clone_dir: str) -> str:
    """Run % git branch; and return name of current branch.

    :raises: `RuntimeError`
    :raises: `ValueError`
    """
    git_branch_proc = subprocess.Popen(
        ["git", "branch", "--no-color"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=git_clone_dir,
    )
    out, err = git_branch_proc.communicate()
    retcode = git_branch_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            "git branch has returned {:d}, err: {:s}".format(
                retcode, err.decode("utf-8")
            )
        )

    for line in out.decode("utf-8").splitlines():
        if line.startswith("*"):
            return line.strip().split(" ", 1)[1]

    raise ValueError("Failed to get branch name.")


def git_clone(git_clone_dir: str, git_repo: str) -> None:
    """Clone given git repository into given directory.

    :raises: `RuntimeError`
    """
    git_clone_proc = subprocess.Popen(
        ["git", "clone", git_repo, git_clone_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, err = git_clone_proc.communicate()
    retcode = git_clone_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            "git clone has returned {:d}, err: {:s}".format(
                retcode, err.decode("utf-8")
            )
        )


def git_pull(git_clone_dir: str) -> str:
    """Run % git pull; and return it's stdout.

    :raises: `RuntimeError`
    """
    git_pull_proc = subprocess.Popen(
        ["git", "pull"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=git_clone_dir,
    )
    out, err = git_pull_proc.communicate()
    retcode = git_pull_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            "git pull has returned {:d}, err: {:s}".format(
                retcode, err.decode("utf-8")
            )
        )

    return parse_pull_output(out.decode("utf-8"))


def git_show(git_clone_dir: str, git_ref: str) -> List[str]:
    """Run % git show; and return commit hash and title as list of tuples."""
    git_show_proc = subprocess.Popen(
        ["git", "show", "--pretty=oneline", "-s", git_ref],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=git_clone_dir,
    )
    out, err = git_show_proc.communicate()
    retcode = git_show_proc.returncode
    if retcode != 0:
        raise RuntimeError(
            "git show has returned {:d}, err: {:s}".format(
                retcode, err.decode("utf-8")
            )
        )

    return parse_commits(out.decode("utf-8"))


def main():
    """Post new commits in given repository to Slack."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger("git-commits2slack")
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    try:
        slack_token = rss2slack.get_slack_token()

        if not os.path.isdir(args.git_clone_dir):
            git_clone(args.git_clone_dir, args.git_repo)

        os.chdir(args.git_clone_dir)
        commit_ref = git_pull(args.git_clone_dir)
        if not commit_ref:
            logger.info("No new commits.")
            sys.exit(0)

        commits = git_show(args.git_clone_dir, commit_ref)
        if not commits:
            # FIXME(zstyblik): error? send message to Slack?
            logger.warning("There should be new commits, but we have none.")
            sys.exit(0)

        repo_name = os.path.basename(args.git_clone_dir)
        branch_name = git_branch(args.git_clone_dir)
        commit_count = len(commits)

        msg_blocks = [
            format_commit_message(args.git_web, commit[0], commit[1])
            for commit in commits
        ]

        heading = format_heading(
            args.git_web, branch_name, repo_name, commit_count
        )
        msg_blocks.insert(0, heading)

        slack_client = rss2slack.get_slack_web_client(
            slack_token, args.slack_base_url, args.slack_timeout
        )
        rss2slack.post_to_slack(
            logger,
            msg_blocks,
            slack_client,
            args.slack_channel,
        )
    except Exception:
        logger.debug("%s", traceback.format_exc())
        # TODO(zstyblik):
        # 1. touch error file
        # 2. send error message to the channel
    finally:
        sys.exit(0)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--git-clone-dir",
        dest="git_clone_dir",
        required=True,
        type=str,
        help="Directory where git repository will be cloned into.",
    )
    parser.add_argument(
        "--git-repository",
        dest="git_repo",
        required=True,
        type=str,
        help="git repository to track.",
    )
    parser.add_argument(
        "--git-web",
        dest="git_web",
        type=str,
        default="http://localhost",
        help="git web interface, resp. base URL, for given repository.",
    )
    parser.add_argument(
        "--slack-base-url",
        dest="slack_base_url",
        type=str,
        default=rss2slack.SLACK_BASE_URL,
        help="Base URL for Slack client.",
    )
    parser.add_argument(
        "--slack-channel",
        dest="slack_channel",
        type=str,
        required=True,
        help="Name of Slack channel to send formatted news to.",
    )
    parser.add_argument(
        "--slack-timeout",
        dest="slack_timeout",
        type=int,
        default=rss2irc.HTTP_TIMEOUT,
        help="Slack API Timeout. Defaults to {:d} seconds.".format(
            rss2irc.HTTP_TIMEOUT
        ),
    )
    parser.add_argument(
        "--sleep",
        dest="sleep",
        type=int,
        default=2,
        help=(
            "Sleep between messages in order to avoid "
            "possible excess flood/API call rate limit."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="store_true",
        default=False,
        help="Increase logging verbosity.",
    )
    return parser.parse_args()


def parse_commits(output: str) -> List[str]:
    """Return commit hash and title as list of tuples.

    :param output: Output of % git show; command.
    """
    return [
        line.strip().split(" ", 1)
        for line in output.splitlines()
        if line.strip() != ""
    ]


def parse_pull_output(output: str) -> str:
    """Parse output of % git pull; and return git reference."""
    for line in output.splitlines():
        if RE_GIT_AUTD.search(line.strip()):
            return ""
        elif RE_GIT_UPDATING.search(line.strip()):
            return line.split(" ")[1]

    return ""


if __name__ == "__main__":
    main()
