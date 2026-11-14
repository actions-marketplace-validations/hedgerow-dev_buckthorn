#!/bin/sh
# Scan a held-out corpus with the frozen Buckthorn image and GuardDog 3.2.0.
# Offline, read-only, no capabilities; only rule ids, files and lines are kept.
# Usage: sh run_scans.sh VOLUME_OR_DIR LIST OUT_PREFIX
#   malicious, on the mini: sh run_scans.sh heldout-malreg lists/malicious-scan-list.txt out/malicious
#   benign, on Azure:       sh run_scans.sh ~/heldout/data lists/benign-scan-list.txt out/benign
set -eu
src=$1; list=$(realpath "$2"); out=$3
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$(dirname "$out")"; chmod 777 "$(dirname "$out")"
outdir=$(realpath "$(dirname "$out")"); base=$(basename "$out")
run() {
  podman run --rm --network none --read-only --cap-drop all --security-opt no-new-privileges \
    --tmpfs /tmp:size=3g --tmpfs /home/scanner:size=200m --tmpfs /work:size=3g,mode=1777 \
    -v "$src":/h:ro -v "$here":/driver:ro -v "$list":/list.txt:ro -v "$outdir":/out "$@"
}
run localhost/buckthorn-scan:heldout-c80b090 \
  python -I /driver/scan_heldout.py buckthorn /h /list.txt "/out/$base-buckthorn.jsonl" /work
run localhost/guarddog:3.2.0 \
  python -I /driver/scan_heldout.py guarddog /h /list.txt "/out/$base-guarddog.jsonl" /work
gzip -f "$outdir/$base-buckthorn.jsonl" "$outdir/$base-guarddog.jsonl"
echo SCANS DONE
