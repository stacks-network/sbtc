#!/usr/bin/env bash

# shellcheck disable=SC2016
if test "$BASH" = "" || "$BASH" -uc 'a=();true "${a[@]}"' 2>/dev/null; then
	# Bash 4.4, Zsh
	set -Eeuo pipefail
else
	# Bash 4.3 and older chokes on empty arrays with set -u.
	set -Eeo pipefail
fi
if shopt | grep globstar &>/dev/null; then
	shopt -s nullglob globstar || true
fi

if [[ -n ${DEBUG+x} ]]; then
	set -x
fi

make lint
result=$?

if [[ ${result} -ne 0 ]]; then
	echo '`make lint` has found some code/style issues, fix them first.'
fi

exit $result
