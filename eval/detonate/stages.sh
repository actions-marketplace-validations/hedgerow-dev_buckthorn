#!/bin/bash
# The three moments a package's code can run without being called: install, import, start-up.
S=$(ls /opt/det/in/)
echo "== install $S"
DET_STAGE=install timeout 90 python3 -m pip install --no-deps --no-index --no-build-isolation \
  --no-cache-dir --break-system-packages "/opt/det/in/$S"
echo "install exit $?"
echo "== import"
DET_STAGE=import timeout 40 python3 /opt/det/import_new.py
echo "== start"
DET_STAGE=start timeout 20 python3 -c "pass"
echo "== wait"
sleep 30
echo "== done"
