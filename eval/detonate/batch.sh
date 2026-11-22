#!/usr/bin/env bash
# Detonate each picked sample, one at a time. Run as root on the KVM host.
set -u
cd "$(dirname "$0")" || exit 1
while read -r group path; do
  [ -z "$path" ] && continue
  name=$(echo "$path" | cut -d/ -f2); file=samples/$name/$(basename "$path")
  [ -f "results/$name/strace.log" ] && { echo "skip $name"; continue; }
  echo "=== $group $name $(sha256sum "$file" | cut -c1-16)"
  bash det-pypi-host.sh "$PWD/$file" "$name" < /dev/null 2>&1 | tail -3
done < pick.txt
echo BATCH_DONE
