#!/bin/sh
# Fetch the archives pypi_malregistry added after the tuning snapshot into a
# Podman volume on the Mac mini. Network on, but nothing is unpacked or run:
# git writes the archive files as they are stored upstream.
# Usage (on the mini): sh fetch_malreg.sh PATHS_FILE
set -eu
paths=$(realpath "$1")
podman volume create heldout-malreg >/dev/null 2>&1 || true
podman run --rm --cap-drop all \
  --security-opt no-new-privileges \
  -v heldout-malreg:/v -v "$paths":/paths.txt:ro --entrypoint sh docker.io/alpine/git -c '
    set -eu
    rm -rf /v/mr
    git clone -q --filter=blob:none --no-checkout --sparse \
      https://github.com/lxyeternal/pypi_malregistry.git /v/mr
    cd /v/mr
    sed "s|^|/|" /paths.txt | git sparse-checkout set --no-cone --stdin
    git checkout -q b85fe7743597b850b72b0ac9cb815f88a301ef10
    git log -1 --format="%H %ci"
    find . -path ./.git -prune -o -type f -print | grep -v "^./README" | wc -l
  '
