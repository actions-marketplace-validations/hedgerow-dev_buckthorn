"""Rebuild each DataDog npm sample into an npm tarball and scan it with buckthorn.

Runs inside a --network none container. Each sample is an unpacked tree in an
encrypted zip; members are copied from the zip into a new .tgz on tmpfs, then
scanned in process. Nothing is installed or run. Results keep rule ids,
severities, member paths and script names, never finding messages.
Usage: python -I run_npm.py SAMPLES_DIR OUT.jsonl WORK_DIR
"""

import io
import json
import re
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
            record = {"n": n, "category": category, "version": version}
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
                    record["outside_root"] = len(infos) - len(keep)
                    record["files"] = len(keep)
                    record["js"] = sum(i.filename.endswith((".js", ".mjs", ".cjs")) for i in keep)
                    record["exts"] = sorted(
                        {Path(i.filename).suffix.lower() or "(none)" for i in keep}
                    )
                    # Key names only, never values: values can hold live channels.
                    try:
                        manifest = json.loads(zf.read(manifests[0], pwd=PWD))
                        record["keys"] = sorted(manifest)[:40]
                        deps = manifest.get("dependencies") or {}
                        record["deps"] = len(deps)
                        record["dep_url"] = any(
                            re.search(r"https?:|git[+:]|file:|github:", str(v))
                            for v in deps.values()
                        )
                    except Exception:
                        record["keys"] = None
                    unscoped = name.split("@")[-1]
                    path = work / f"{unscoped}-{version}.tgz"
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
                        [f.rule_id, f.severity.value, f.file_path, f.metadata.get("script")]
                        for f in findings
                    ]
            except Exception as exc:  # recorded per sample, the run goes on
                record["status"] = "error"
                record["error"] = type(exc).__name__
            fh.write(json.dumps(record) + "\n")
            print(n, record["status"], record.get("verdict"), flush=True)


if __name__ == "__main__":
    main()
