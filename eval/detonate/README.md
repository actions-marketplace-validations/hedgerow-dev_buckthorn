# Detonation harness

Buckthorn reads a package and says what would run. This harness checks that
claim on real samples: it runs the package inside a Firecracker microVM and
records what it does at the three moments Buckthorn reads.

1. **Install:** `pip install` of the archive, no dependencies, no index.
2. **Import:** every top-level module the package installed.
3. **Start-up:** a fresh `python3 -c pass`, so any `.pth` file runs.

Code that only runs when you call a function is out of scope here, as it is
for Buckthorn's default rules.

## How it is contained

- One sample per microVM, run under the jailer as uid 65534.
- A private network namespace with one tap device and no default route.
- nftables drops every packet in and out, and logs each attempt.
- A listener on the host that the guest must never reach. Any byte in
  `collector.log` means the containment failed.
- The host copies the archive's bytes into the guest disk. It never installs,
  unpacks or imports it.

Run it only on a dedicated KVM host that holds nothing you care about: never a
laptop, never a shared cloud account.

## What it records

- `strace.log`: programs run, files opened, connects and sends, deletes and renames.
- `audit.log`: a Python audit hook (`sitecustomize.py`) in every guest Python
  process, tagged with the stage it ran in.
- `denied-packets.log` and `nft-counter.txt`: every packet the firewall dropped.
- `changed-files.txt`: files written after the stages started.
- Decoy secrets with fake values: an SSH key, AWS credentials, `.env`,
  `.pypirc`, a Solana keypair and a MetaMask vault. Opening one shows in strace.

`summarize.py` turns each run into a short report. It subtracts what the
control run shows (pip's own programs and caches), so what is left is the
package's doing.

## Running it

You need Linux with `/dev/kvm`, `firecracker` and `jailer` in
`/usr/local/bin`, `nft` and `nc`, and in `/opt/fc` a guest kernel
(`vmlinux`) and an Ubuntu 24.04 root image (`rootfs.ext4`) with Python 3.12
and `strace`. For another folder, pass it as `sudo FC_DIR=/path ./script`
(sudo drops the variable otherwise).

1. Build the guest image. Put the pip, setuptools (80.9.0 or later) and wheel
   wheels from PyPI in `wheels/`, then run `sudo ./prep-image.sh wheels`.
2. Build and run the control. It is a test package that reads the decoy AWS
   file and tries `192.0.2.1:80` (a documentation address) at install, and
   runs `id` at import. Each layer should record all three.

   ```bash
   mkdir -p build && cp -r control build/detcontrol-0.1 && tar czf detcontrol-0.1.tar.gz -C build detcontrol-0.1
   ```

   ```bash
   sudo ./det-pypi-host.sh "$PWD/detcontrol-0.1.tar.gz" control
   ```

3. Put each sample at `samples/NAME/FILE`, and list them in `pick.txt`, one
   per line as `GROUP DIR/NAME/FILE`. GROUP is a free label for your own notes.
4. Run them one at a time, then summarise.

   ```bash
   sudo ./batch.sh
   ```

   ```bash
   python3 summarize.py results
   ```

## Limits

- No network means a second-stage payload never arrives. You see the attempt
  (the address, the command), not what it would have fetched.
- A payload that waits for a date, a host name or a CI variable may stay quiet.
  A quiet run is not proof the package is harmless.
- Each run gets one vCPU, 1 GiB and about 200 seconds.

## Keep results out of git

`results/`, `samples/` and `pick.txt` are ignored. Results hold live attacker
addresses and full traces of malware. Keep them on the detonation host.
