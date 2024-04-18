#!/usr/bin/env bash
set -e
set -u

python3 -m flake8 \
    . \
    --ignore=W503 \
    --application-import-names="app,settings" \
    --import-order-style=pycharm \
    --max-line-length=80 \
    --show-source \
    --count \
    --statistics
