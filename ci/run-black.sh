#!/usr/bin/env bash
set -e
set -u


MODE=${1:?Mode must be given.}

if [ "${MODE}" = "check" ]; then
    black_arg=" --check"
elif [ "${MODE}" = "diff" ]; then
    black_arg=" --diff"
elif [ "${MODE}" = "format" ]; then
    black_arg=""
else
    printf "Mode '%s' is not supported.\n" "${MODE}" 1>&2
    exit 1
fi

cd "$(dirname "${0}")/.."

# shellcheck disable=SC2086
find . ! -path '*/\.*' -name '*.py' -print0 | \
    xargs -0 -- python3 -m black ${black_arg} -l 80
