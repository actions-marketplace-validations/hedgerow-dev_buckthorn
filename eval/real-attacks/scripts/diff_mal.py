"""Diff each sample against the version before it: what the bump adds.

Runs inside a --network none, read-only container. The sample is rebuilt into
a .tgz on tmpfs as run_mal.py does, then `buckthorn diff` logic runs in
process. Results keep rule ids, severities, member paths and script names,
never finding messages. Usage: python -I diff_mal.py SAMPLES_DIR OUT.jsonl WORK_DIR
"""

import io
import json
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

from buckthorn.cli import _diff
from buckthorn.findings import verdict

PWD = b"infected"


def rebuild(zpath, path):
    zf = zipfile.ZipFile(zpath)
    infos = [i for i in zf.infolist() if not i.is_dir()]
    manifests = sorted(
        (i.filename for i in infos if i.filename.endswith("/package/package.json")),
        key=lambda x: x.count("/"),
    )
    if not manifests:
        return False
    root = manifests[0][: -len("package.json")]
    with tarfile.open(path, "w:gz") as tf:
        for i in infos:
            if i.filename.startswith(root):
                data = zf.read(i, pwd=PWD)
                ti = tarfile.TarInfo("package/" + i.filename[len(root) :])
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return True


def main():
    samples, out, work = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    rows = [line.split("\t") for line in (samples / "prev.tsv").read_text().splitlines()]
    with out.open("w") as fh:
        for zname, name, version, prev, status in rows:
            record = {"sample": zname, "name": name, "version": version, "prev": prev}
            unscoped = name.split("/")[-1]
            old = work / f"{unscoped}-{prev}.tgz"
            new = work / f"{unscoped}-{version}.tgz"
            try:
                if status != "ok":
                    record["status"] = "no previous version"
                elif not rebuild(samples / "zips" / zname, new):
                    record["status"] = "no package root"
                else:
                    shutil.copyfile(samples / "prev" / zname.replace(".zip", ".tgz"), old)
                    result = _diff(str(old), str(new), None)
                    record["status"] = "diffed"
                    record["verdict"] = verdict(result.findings)
                    record["findings"] = [
                        [f.rule_id, f.severity.value, f.file_path, f.metadata.get("script")]
                        for f in result.findings
                    ]
            except Exception as exc:  # recorded per sample, the run goes on
                record["status"] = "error"
                record["error"] = type(exc).__name__
            finally:
                old.unlink(missing_ok=True)
                new.unlink(missing_ok=True)
            fh.write(json.dumps(record) + "\n")
            print(zname, record["status"], record.get("verdict"), flush=True)


if __name__ == "__main__":
    main()
