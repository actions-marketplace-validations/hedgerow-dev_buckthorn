#!/bin/sh
# On the mini: redacted view (strings and comments replaced) of each archive named
# in LIST, offline, read-only. Usage: sh show_many.sh LIST MAX_LINES [LINE_REGEX]
set -eu
podman run --rm --network none --read-only --cap-drop all --security-opt no-new-privileges \
  -v heldout-malreg:/h:ro -v ~/bkt-run/heldout/scripts:/driver:ro -v "$(realpath "$1")":/list.txt:ro \
  localhost/buckthorn-scan:heldout-c80b090 sh -c \
  "while read s; do echo \"##### \$s\"; python -I /driver/show_redacted.py /h \"\$s\" $2 '${3:-}'; done < /list.txt"
