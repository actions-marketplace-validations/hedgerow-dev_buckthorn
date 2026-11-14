#!/bin/sh
# On the mini: where risky calls sit in each sampled miss (call names only), offline.
# triage-drv holds ../../datadog-malicious/scripts/{triage,run_corpus}.py and
# ../../pypi-malregistry/scripts/triage_archives.py.
set -eu
cd ~/bkt-run/heldout
mkdir -p triage-out && chmod 777 triage-out
podman run --rm --network none --read-only --cap-drop all --security-opt no-new-privileges \
  -v heldout-malreg:/h:ro -v ~/bkt-run/heldout/triage-drv:/driver:ro \
  -v ~/bkt-run/heldout/lists/triage-malicious-misses.txt:/list.txt:ro -v ~/bkt-run/heldout/triage-out:/out \
  localhost/buckthorn-scan:heldout-c80b090 python -I /driver/triage_archives.py /h /list.txt /out/misses-calls.jsonl
echo TRIAGE DONE
