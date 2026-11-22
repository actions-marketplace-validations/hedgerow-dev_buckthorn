#!/usr/bin/env bash
# Build $FC_DIR/rootfs-pypi.ext4: the plain guest image plus pip, setuptools and
# wheel (benign wheels from PyPI, unpacked into dist-packages) and an audit-hook
# sitecustomize, so every Python process in the guest logs what it does.
# Usage (root, on the KVM host): prep-image.sh WHEEL_DIR
set -euo pipefail
WHEELS=$1; HERE=$(cd "$(dirname "$0")" && pwd)
FC=${FC_DIR:-/opt/fc}; SRC=$FC/rootfs.ext4; DST=$FC/rootfs-pypi.ext4
cp --sparse=always "$SRC" "$DST.tmp"
mkdir -p /mnt/detprep; mount -o loop "$DST.tmp" /mnt/detprep
trap 'umount /mnt/detprep 2>/dev/null || true' EXIT
SITE=/mnt/detprep/usr/lib/python3/dist-packages
for w in "$WHEELS"/*.whl; do python3 -m zipfile -e "$w" "$SITE"; done
SC=/mnt/detprep/usr/lib/python3.12/sitecustomize.py
if [ -L "$SC" ]; then SC=/mnt/detprep$(readlink -f "$SC" | sed 's|^/mnt/detprep||'); fi
cat "$HERE/sitecustomize.py" >> "$SC"
rm -f /mnt/detprep/usr/lib/python3.12/EXTERNALLY-MANAGED
umount /mnt/detprep; trap - EXIT
mv "$DST.tmp" "$DST"
echo "built $DST"
