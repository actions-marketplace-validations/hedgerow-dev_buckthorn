"""Write the hand triage of the 50 sampled malicious misses as CSV.

Reasons come from reading each sample's call locations (triage_archives.py) and a
redacted view (show_redacted.py) inside the container; templates shared by several
packages were read once and matched by identical call layout.
Usage: python3 -I write_miss_triage.py LIST BKT.jsonl.gz OUT_CSV
"""

import collections
import csv
import gzip
import json
import sys

LATER = "out of scope: payload runs only when the user calls it"
REASONS = {
    # Downloader templates: fetch(url) or run(url) downloads code and execs or runs it.
    **{p: (LATER, "downloads code from a URL and execs it, only when fetch/pull is called")
       for p in ("acoustichub", "evalstream", "modelworks", "phonemeprobe", "speechprobe",
                 "ttsweaver", "vocabblend")},
    **{p: (LATER, "run(url) downloads a script and runs it in a child Python")
       for p in ("brookworker", "cobbleload", "ferretqueue", "flintqueue", "otterload",
                 "reedworker", "thornqueue", "workslip")},
    # Miner harnesses aimed at notebook users: harness.run() fetches and starts a miner.
    **{p: (LATER, "module builds Harness(); run() fetches native binaries and starts a miner")
       for p in ("caoxiltts", "voxcpmruntime", "voxcpmui3", "voxel-tts")},
    "faiss-cpu-avx512": (LATER, "start() downloads a native binary and supervises it (miner)"),
    "aiosendletter": (LATER, "init() elevates on Windows and posts a zipped app-data folder"),
    "pullgetsage": (LATER, "init() posts a zipped app-data folder, same template as aiosendletter"),
    "proxyrubika": (LATER, "starts() posts data to a server"),
    "pyjstat-smooth": (LATER, "trojanised pyjstat: uniquify() calls _ensure_compat, which collects files; runs on normal library use"),
    "index-forum": (LATER, "same trojanised pyjstat as pyjstat-smooth"),
    "starlette-healthchecks": (LATER, "configure_logging() sends the host's public IP to a log host"),
    "extera-plugin-runtime": (LATER, "BackupRuntime uploads to a server when used"),
    "media-manager5": (LATER, "remote-control client; runs from main() or a scheduled task the user's call registers"),
    "minecraftaccfinder@0.3.0": (LATER, "browser and game-account stealer started from the console script"),
    "fabtoolkit": (LATER, "selftest() runs embedded child code; started by python -m"),
    "hello-bat-fwi9": (LATER, "hello() writes and runs a .bat; called by the user or console script"),
    "prosocks": (LATER, "SOCKS proxy agent that registers with a server; console script"),
    "vercel-runtime-python": (LATER, "device info posted only under __main__ (dependency-confusion probe)"),
    "zagents-message-bus": (LATER, "ping to a callback only under __main__"),
    "zyto": (LATER, "image download-and-open helpers; also ships Helper.exe in the sdist, which no sdist rule checks"),
    "shortneer": ("payload in native code", "shortname() calls a compiled _core module; native code is not read"),
    "aitextutils-py": ("payload in a dependency", "clean_text() calls setup() from aitextkit-py, its dependency"),
    "webreader": ("payload in a dependency", "no risky call in the sample; depends on an unknown package"),
    "saeka": ("no payload in the sample", "setup.py and an entry point only; the module it names is not shipped"),
    "dedh-devops-automation": ("no payload in the sample", "placeholder package"),
    "dbt-adapter": ("no payload in the sample", "placeholder package (0.0.0)"),
    "minecraftaccfinder@0.1.0": ("no payload in the sample", "placeholder that prints a banner"),
    "test-workalendar-internal": ("no payload in the sample", "workday helper; nothing risky (likely a dependency-confusion probe)"),
    "claudeopusfile": ("rule gap (in scope)", "setup.py calls compat._ensure_compat() at install; it execs zlib+b85-decoded code through getattr(builtins, name) with the name built by chr() into a module variable, which HIDE-001 does not follow"),
}


def reason(sample):
    _, name, version = sample.split("/")[:3]
    return REASONS.get(f"{name}@{version}") or REASONS[name]


lst, bkt, out = sys.argv[1:4]
results = {json.loads(l)["sample"]: json.loads(l) for l in gzip.open(bkt, "rt")}
rows = []
for s in (l.strip() for l in open(lst) if l.strip()):
    r = results[s]
    cat, note = reason(s)
    rows.append({"sample": s, "verdict": r.get("verdict") or r.get("status"),
                 "rules": " ".join(sorted({f["rule_id"] for f in r.get("findings", [])})),
                 "reason": cat, "note": note})
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
print(collections.Counter(r["reason"] for r in rows))
print(collections.Counter(r["verdict"] for r in rows))
