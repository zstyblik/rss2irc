#!/usr/bin/env bash
set -e
set -u

cd "$(dirname "${0}")/.."

python3 -m flake8 \
    . \
    --ignore=W503 \
    --application-import-names="cache_stats,gh2slack,git_commits2slack,phpbb2slack,rss2irc,rss2slack,lib" \
    --import-order-style=pycharm \
    --max-line-length=80 \
    --show-source \
    --count \
    --statistics
