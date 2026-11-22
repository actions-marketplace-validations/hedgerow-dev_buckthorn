#!/bin/bash
# Guest init: install the sample with pip, import what it installed, start Python again
# (a .pth runs then), and wait. Everything under strace; every Python process has the
# audit hook from sitecustomize.
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
export HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /var/log/det
cd /root || exit 1
echo "DET_START"
timeout 200 strace -f -tt -s 300 -e trace=execve,connect,sendto,openat,unlink,unlinkat,rename,renameat \
  -o /var/log/det/strace.log /bin/bash /opt/det/stages.sh > /var/log/det/stdout.log 2>&1
echo "DET_EXIT=$?"
ps -eo pid,ppid,args > /var/log/det/ps-after.txt 2>&1
sync
reboot -f
