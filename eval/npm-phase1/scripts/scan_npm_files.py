"""Scan each .tgz under a folder with buckthorn, in process, and record rule ids.

Usage: python -I scan_npm_files.py DIR OUT.jsonl
"""

import json
import sys
from pathlib import Path

from buckthorn.findings import verdict
from buckthorn.scan import scan_artifact

root, out = Path(sys.argv[1]), Path(sys.argv[2])
with out.open("w") as fh:
    for path in sorted(root.rglob("*.tgz")):
        findings = scan_artifact(path)
        record = {
            "file": str(path.relative_to(root)),
            "verdict": verdict(findings),
            "findings": [
                [f.rule_id, f.severity.value, f.file_path, f.metadata.get("script")]
                for f in findings
            ],
        }
        fh.write(json.dumps(record) + "\n")
        print(record["file"], record["verdict"], flush=True)
