#!/bin/sh
# On the mini: hash held-out and tuning archives, offline, corpora read-only.
set -eu
cd ~/bkt-run/heldout
mkdir -p hashes
run() {
  podman run --rm --network none --read-only --cap-drop all --security-opt no-new-privileges \
    -v ~/bkt-run/heldout/scripts:/driver:ro -v ~/bkt-run/heldout/hashes:/out "$@"
}
I=localhost/buckthorn-scan:heldout-c80b090
run -v heldout-malreg:/h:ro $I python -I /driver/file_hashes.py files /h/mr /out/heldout-malreg.jsonl
run -v bkt-malreg:/c:ro $I python -I /driver/file_hashes.py files /c/mr /out/tuning-malreg.jsonl
run -v bkt-malcorpus:/c:ro $I python -I /driver/file_hashes.py datadog /c/ds/samples/pypi /out/tuning-datadog.jsonl
run -v bkt-benign:/c:ro $I python -I /driver/file_hashes.py files /c /out/tuning-benign.jsonl
echo HASHES DONE
