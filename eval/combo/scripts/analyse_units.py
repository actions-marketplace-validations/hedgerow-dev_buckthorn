"""Tuning only: how many artifacts each candidate combination flags, from units.py output.

Reads JSON lines of call names and rule kinds; no sample is opened. Some
candidates use kinds that were measured in tuning run 2 (detached, load, write,
names_secret) and removed from buckthorn/code.py after no rule used them.
Usage: python analyse_units.py BENIGN.jsonl MALREG.jsonl DATADOG.jsonl
"""

import json
import sys

CORPORA = ("benign", "malreg", "datadog")


def kinds(unit):
    found = set()
    for kind, detail in unit["hits"]:
        found.add(kind)
        if kind == "network":
            found.add("fetch_cmd" if detail.startswith("runs a command") else "http")
        if kind == "hidden":
            found.add("exec")
        if kind in ("secrets", "names_secret"):
            found.add("cred")
        if kind in ("persistence", "names_persistence"):
            found.add("persist")
        if kind == "detached" and "." not in detail.rpartition("(")[2]:
            found.add("detached_cmd")  # a command line (nohup, start /b), not a call or flag
    return found


def has(*names):
    return lambda k: all(n in k for n in names)


CANDIDATES = {
    "net+exec": has("network", "exec"),
    "http+exec": has("http", "exec"),
    "net+load": has("network", "load"),
    "net+process": has("network", "process"),
    "http+process": has("http", "process"),
    "net+write+process": has("network", "write", "process"),
    "net+write+load": has("network", "write", "load"),
    "cred+net": has("cred", "network"),
    "secrets+net": has("secrets", "network"),
    "names_secret+net": has("names_secret", "network"),
    "environ+net": has("environ", "network"),
    "decode+exec": has("decode", "exec"),
    "decode+process": has("decode", "process"),
    "persist+any": lambda k: "persist" in k and bool(k & {"network", "process", "exec", "write"}),
    "persist+net": has("persist", "network"),
    "persist+process": has("persist", "process"),
    "detached+net": has("detached", "network"),
    "detached_cmd+net": has("detached_cmd", "network"),
    "net+runs_written": has("network", "runs_written"),
    "decode+runs_written": has("decode", "runs_written"),
    "runs_written": has("runs_written"),
    "redirect+process": has("redirect", "process"),
    "redirect+net+process": has("redirect", "network", "process"),
    "net+exec|load|rw": lambda k: "network" in k and bool(k & {"exec", "load", "runs_written"}),
    "net+exec|rw": lambda k: "network" in k and bool(k & {"exec", "runs_written"}),
    "detached+exec": has("detached", "exec"),
    "detached+decode": has("detached", "decode"),
}


def load(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh]


def hits_of(record, predicate, scope):
    for f in record.get("files", []):
        if scope == "pkg" and f["whole"] or scope == "whole" and not f["whole"]:
            continue
        for unit in f.get("units", []):
            if predicate(kinds(unit)):
                return True
    return False


def main():
    data = {
        name: [r for r in load(p) if r.get("status") == "scanned"]
        for name, p in zip(CORPORA, sys.argv[1:4], strict=True)
    }
    for name, records in data.items():
        flagged = sum(r["verdict"] == "flagged" for r in records)
        errors = sum(1 for r in records for f in r.get("files", []) if f.get("error"))
        print(
            f"{name}: {len(records)} scanned, today flagged {flagged}, call-time files not parsed {errors}"
        )
    print()
    head = "candidate".ljust(20) + "".join(f"{c:>18}" for c in CORPORA)
    for scope in ("all", "pkg", "whole"):
        print(f"scope={scope}  (total / new over today)")
        print(head)
        for label, predicate in CANDIDATES.items():
            row = label.ljust(20)
            for name in CORPORA:
                hit = [r for r in data[name] if hits_of(r, predicate, scope)]
                new = [r for r in hit if r["verdict"] != "flagged"]
                row += f"{len(hit):>10} / {len(new):<5}"
            print(row)
        print()
    print("HIDE/EXFIL kinds in newly read whole files (total / new):")
    for kind in ("hidden", "encoded", "discord", "telegram"):
        row = kind.ljust(20)
        for name in CORPORA:
            hit = [
                r for r in data[name] if any(kind in f.get("hide", []) for f in r.get("files", []))
            ]
            new = [r for r in hit if r["verdict"] != "flagged"]
            row += f"{len(hit):>10} / {len(new):<5}"
        print(row)


if __name__ == "__main__":
    main()
