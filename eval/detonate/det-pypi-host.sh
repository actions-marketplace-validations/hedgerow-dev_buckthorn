#!/usr/bin/env bash
# Run one suspect PyPI archive inside a Firecracker microVM (jailer, no route out,
# default-deny): pip-install it, import what it installed, start Python again, and record
# what it tries to do.
# The host only copies the archive's bytes; it never installs or unpacks it.
#
# Usage (root, on the KVM host): det-pypi-host.sh SAMPLE_FILE RUN_NAME
set -euo pipefail
SAMPLE=$1; NAME=$2
FC=${FC_DIR:-/opt/fc}   # guest kernel and images
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/results/$NAME
NS=bkt-detpy
TAP_IP=10.200.98.1
GUEST_IP=10.200.98.2
# NAME comes from a sample's directory and ends up in paths removed as root: check it.
[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,50}$ ]] || { echo "bad run name: $NAME"; exit 1; }
JID=detpy-${NAME//[^A-Za-z0-9-]/-}   # the jailer allows letters, digits and dashes only
CHROOT_BASE=/srv/bkt-detpy
ROOT=$CHROOT_BASE/firecracker/$JID/root
MNT=/mnt/detpy
[ -e /dev/kvm ] && [ -f "$SAMPLE" ] && [ -f "$FC/rootfs-pypi.ext4" ] || { echo "need /dev/kvm, $SAMPLE and rootfs-pypi.ext4"; exit 1; }
mkdir -p "$OUT"

OLD_NFLOG=$(sysctl -n net.netfilter.nf_log_all_netns)
sysctl -qw net.netfilter.nf_log_all_netns=1   # let the sandbox netns log its denials; restored on exit
cleanup() {
  sysctl -qw net.netfilter.nf_log_all_netns="$OLD_NFLOG"
  umount "$MNT" 2>/dev/null || true
  ip netns del $NS 2>/dev/null || true
  [ -n "${COLLECTOR_PID:-}" ] && kill $COLLECTOR_PID 2>/dev/null || true
  rm -rf "$CHROOT_BASE/firecracker/$JID"
}
trap cleanup EXIT

# --- isolated namespace: one tap, no uplink, no default route ---
ip netns del $NS 2>/dev/null || true
ip netns add $NS
ip netns exec $NS ip link set lo up
ip netns exec $NS ip tuntap add dev tap0 mode tap user 65534
ip netns exec $NS ip addr add $TAP_IP/30 dev tap0
ip netns exec $NS ip link set tap0 up
ip netns exec $NS ip route show | grep -q '^default' && { echo "FAIL: default route"; exit 1; }

# --- default-deny everything, count and log each attempt ---
ip netns exec $NS nft -f - <<NFT
table inet bkt_detpy {
  counter denied { }
  chain input {
    type filter hook input priority filter; policy drop;
    log prefix "bkt-detpy-in " counter name "denied" drop
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    log prefix "bkt-detpy-fw " counter name "denied" drop
  }
  chain output {
    type filter hook output priority filter; policy drop;
    log prefix "bkt-detpy-out " counter name "denied" drop
  }
}
NFT

# --- oracle: a collector on the host the guest must never reach ---
: > "$OUT/collector.log"
( while true; do timeout 300 nc -l -p 9091 >> "$OUT/collector.log" 2>/dev/null || true; done ) &
COLLECTOR_PID=$!

# --- private copy of the guest disk with the archive, the stages and decoys ---
mkdir -p "$ROOT"
cp "$FC/vmlinux" "$ROOT/vmlinux"
cp --sparse=always "$FC/rootfs-pypi.ext4" "$ROOT/rootfs.ext4"
mkdir -p "$MNT"
mount -o loop "$ROOT/rootfs.ext4" "$MNT"
mkdir -p "$MNT/opt/det/in" "$MNT/var/log/det"
cp "$SAMPLE" "$MNT/opt/det/in/$(basename "$SAMPLE")"
install -m0644 "$HERE/import_new.py" "$MNT/opt/det/import_new.py"
install -m0755 "$HERE/stages.sh" "$MNT/opt/det/stages.sh"
install -m0755 "$HERE/det-init.sh" "$MNT/usr/local/bin/det-init"
# decoys: plausible targets with fake values only
D=$MNT/root
mkdir -p "$D/.ssh" "$D/.config/solana" "$D/.aws" "$D/.config/pip" \
  "$D/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"
echo "DECOY-SSH-PRIVATE-KEY" > "$D/.ssh/id_rsa"
echo "DECOY_AWS_SECRET_ACCESS_KEY=decoy-not-real" > "$D/.env"
printf '[default]\naws_access_key_id = DECOYKEY\naws_secret_access_key = decoy-not-real\n' > "$D/.aws/credentials"
printf '[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\npassword = pypi-DECOY-not-real\n' > "$D/.pypirc"
echo '[1,2,3,"DECOY-SOLANA-KEYPAIR"]' > "$D/.config/solana/id.json"
echo "DECOY-METAMASK-VAULT" > "$D/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log"
touch "$MNT/opt/det/marker"
umount "$MNT"
chown -R 65534:65534 "$ROOT"

cat > "$ROOT/config.json" <<JSON
{
  "boot-source": {"kernel_image_path": "vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=$GUEST_IP:$TAP_IP:$TAP_IP:255.255.255.252::eth0:off init=/usr/local/bin/det-init"},
  "drives": [{"drive_id":"rootfs","path_on_host":"rootfs.ext4","is_root_device":true,"is_read_only":false}],
  "network-interfaces": [{"iface_id":"eth0","host_dev_name":"tap0"}],
  "machine-config": {"vcpu_count":1,"mem_size_mib":1024}
}
JSON

echo "booting $JID (jailer, uid 65534, netns $NS)"
dmesg -C 2>/dev/null || true
timeout 260 jailer --id "$JID" --exec-file /usr/local/bin/firecracker --uid 65534 --gid 65534 \
  --chroot-base-dir "$CHROOT_BASE" --netns /var/run/netns/$NS \
  -- --no-api --config-file config.json > "$OUT/console.log" 2>&1 || true

# --- evidence ---
ip netns exec $NS nft list counter inet bkt_detpy denied > "$OUT/nft-counter.txt" 2>&1 || true
dmesg | grep bkt-detpy > "$OUT/denied-packets.log" || true
mount -o loop,ro,noload "$ROOT/rootfs.ext4" "$MNT"
cp -r "$MNT/var/log/det/." "$OUT/" 2>/dev/null || true
( cd "$MNT" && find . -xdev -newer opt/det/marker -type f ! -path './var/log/det/*' ! -path './opt/det/*' \
    -printf '%TT %s %p\n' ) > "$OUT/changed-files.txt" 2>/dev/null || true
umount "$MNT"
chmod -R a+rX "$OUT"
echo "collector received: $(wc -c < "$OUT/collector.log") bytes"
echo "denied: $(grep -o 'packets [0-9]*' "$OUT/nft-counter.txt" || echo '?')"
echo "evidence in $OUT"
