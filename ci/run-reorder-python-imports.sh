#!/usr/bin/env bash
set -e
set -u

find . ! -path '*/\.*' -name '*.py' -print0 | \
    xargs -0 -- reorder-python-imports --py311-plus
