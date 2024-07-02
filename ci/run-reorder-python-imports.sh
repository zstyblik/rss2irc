#!/usr/bin/env bash
set -e
set -u

reorder-python-imports --py311-plus `find . ! -path '*/\.*' -name '*.py'`
