"""Rebuild each DataDog npm sample into an npm tarball and scan it with buckthorn.

Phase 1's driver (eval/npm-phase1), keeping lines too. Runs inside a
--network none, read-only container with no Node: each sample is an
unpacked tree in an encrypted zip, copied member by member into a new .tgz
on tmpfs, scanned in process, then deleted. Nothing is installed or run.
Results keep rule ids, severities, member paths, script names and lines,
never finding messages (they can name attacker strings).
Usage: python -I run_mal.py SAMPLES_DIR OUT.jsonl WORK_DIR
"""

import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

from buckthorn.findings import verdict
from buckthorn.scan import scan_artifact

PWD = b"infected"


def main():
    samples, out, work = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    rows = [line.split("\t") for line in (samples / "picked.tsv").read_text().splitlines()]
    with out.open("w") as fh:
        for n, (zname, _, _, dpath) in enumerate(rows):
            _, _, category, name, version, _ = dpath.split("/")
            record = {"n": n, "category": category}
            try:
                zf = zipfile.ZipFile(samples / "zips" / zname)
                infos = [i for i in zf.infolist() if not i.is_dir()]
                manifests = sorted(
                    (i.filename for i in infos if i.filename.endswith("/package/package.json")),
                    key=lambda x: x.count("/"),
                )
                if not manifests:
                    record["status"] = "no package root"
                else:
                    root = manifests[0][: -len("package.json")]
                    keep = [i for i in infos if i.filename.startswith(root)]
                    record["js"] = sum(i.filename.endswith((".js", ".mjs", ".cjs")) for i in keep)
                    path = work / f"{name.split('@')[-1]}-{version}.tgz"
                    with tarfile.open(path, "w:gz") as tf:
                        for i in keep:
                            data = zf.read(i, pwd=PWD)
                            ti = tarfile.TarInfo("package/" + i.filename[len(root) :])
                            ti.size = len(data)
                            tf.addfile(ti, io.BytesIO(data))
                    findings = scan_artifact(path)
                    path.unlink()
                    record["status"] = "scanned"
                    record["verdict"] = verdict(findings)
                    record["findings"] = [
                        [
                            f.rule_id,
                            f.severity.value,
                            f.file_path,
                            f.metadata.get("script"),
                            f.metadata.get("lines"),
                        ]
                        for f in findings
                    ]
            except Exception as exc:  # recorded per sample, the run goes on
                record["status"] = "error"
                record["error"] = type(exc).__name__
            fh.write(json.dumps(record) + "\n")
            print(n, record["status"], record.get("verdict"), flush=True)


if __name__ == "__main__":
    main()
