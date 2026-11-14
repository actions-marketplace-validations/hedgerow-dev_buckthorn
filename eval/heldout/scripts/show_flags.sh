#!/bin/sh
# On the Azure VM: rescan the sampled benign flags offline and print each finding with
# its lines (long strings replaced). Usage: sh show_flags.sh DATA_DIR LIST
set -eu
here=$(cd "$(dirname "$0")" && pwd)
podman run --rm --network none --read-only --cap-drop all --security-opt no-new-privileges \
  --tmpfs /tmp:size=1g -v "$1":/h:ro -v "$here":/driver:ro -v "$(realpath "$2")":/list.txt:ro \
  localhost/buckthorn-scan:heldout-c80b090 python -I /driver/show_flags.py /h /list.txt
