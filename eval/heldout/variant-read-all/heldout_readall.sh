#!/bin/sh
# One-shot held-out scan with the read-all variant image. Same driver, list and
# container flags as the original run. Usage: sh heldout_readall.sh SRC LIST DRIVER_DIR OUT_JSONL CPUS
set -eu
src=$1; list=$(realpath "$2"); driver=$(realpath "$3"); out=$4; cpus=$5
outdir=$(dirname "$out"); mkdir -p "$outdir"; outdir=$(realpath "$outdir")
podman image inspect --format '{{.Id}}' localhost/buckthorn-scan:readall-88fcf87 \
  | grep -qx 845f8643bdbd7e960272af8c88ecb953e78e897d23df62e9c9a8c8576a6ff27f
date -Is > "$outdir/started"
podman run --rm --network none --read-only --cap-drop all --security-opt no-new-privileges \
  --userns keep-id --cpus "$cpus" \
  --tmpfs /tmp:size=3g --tmpfs /home/scanner:size=200m --tmpfs /work:size=3g,mode=1777 \
  -v "$src":/h:ro -v "$driver":/driver:ro -v "$list":/list.txt:ro -v "$outdir":/out \
  localhost/buckthorn-scan:readall-88fcf87 \
  python -I /driver/scan_heldout.py buckthorn /h /list.txt "/out/$(basename "$out")" /work
gzip -f "$out"
date -Is > "$outdir/finished"
