#!/usr/bin/env bash
set -e
set -u

reorder-python-imports `find . ! -path '*/\.*' -name '*.py'`
