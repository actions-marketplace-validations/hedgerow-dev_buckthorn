#!/bin/sh
# scan_dir.sh IMAGE OUTFILE: scan every file in the benign volume, one JSON report per file, offline.
# SCAN_HOST is the ssh target of the machine that holds the volume.
ssh "$SCAN_HOST" "podman run --rm --network none --read-only --cap-drop all --security-opt no-new-privileges -v bkt-benign:/b:ro $1 sh -c 'for f in /b/top100/*; do buckthorn scan --format json \"\$f\" | tr -d \"\\n\"; echo; done'" > $2
