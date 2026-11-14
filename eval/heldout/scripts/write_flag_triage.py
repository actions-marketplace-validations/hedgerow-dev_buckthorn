"""Write the hand triage of the 50 sampled benign flags as CSV.

Each was read from show_flags.py output (findings with their lines) on the Azure VM;
setup commands were checked with an AST walk of setup.py.
Usage: python3 -I write_flag_triage.py LIST BKT.jsonl.gz OUT_CSV
"""

import collections
import csv
import gzip
import json
import sys

REAL, FALSE = "real behaviour", "false alarm"
NOTES = {
    "Arpeggio": (FALSE, "os.system only when argv[-1] starts with 'publish'; pip install never runs it"),
    "Pympler": (REAL, "vendored bottle.py runs eval(compile(...)) at module level"),
    "aiohttp_cors": (REAL, "setup.py execs its own __about__.py through a helper"),
    "albumentations": (REAL, "version check over the network at import"),
    "altgraph": (REAL, "setup.py evals environment markers at install"),
    "apache_airflow_core": (REAL, "example DAGs call requests.get and os.system at module level"),
    "astropy": (REAL, "URL open reached at import through samp/constants.py per the call chain; not checked at run time"),
    "automat": (REAL, "test module shipped in the package runs a shell probe at module level"),
    "avro-python3": (FALSE, "subprocess in a 'lint' setup command; pip install never runs it"),
    "bitsandbytes": (REAL, "ROCm probe with subprocess at import"),
    "bottle": (REAL, "exec(compile(...)) at module level"),
    "chromadb": (REAL, "runs pip install pysqlite3-binary at import when sqlite is old"),
    "clickclick": (FALSE, "requests.get in check_deps(), which is never called (the call is commented out)"),
    "cvxpy": (REAL, "git version lookup at install"),
    "discord_py-2.7.1-py3": (REAL, "libopus DLLs inside a pure-Python wheel"),
    "discord_py-2.7.1.tar": (REAL, "git version lookup at install"),
    "distributed": (REAL, "utils_test.py opens sockets at module level"),
    "flake8_bugbear": (FALSE, "getattr(builtins, name, type) only to test for an exception class; no code is run"),
    "google_generativeai": (REAL, "namespace .pth that touches sys.modules at start-up"),
    "numexpr": (REAL, "core count with subprocess at import"),
    "optree": (REAL, "git at import for the version"),
    "orderedmultidict": (FALSE, "os.system in a 'publish' setup command; pip install never runs it"),
    "pi_heif": (REAL, "build probes with subprocess at install"),
    "pip_system_certs": (REAL, ".pth that patches pip at every start-up"),
    "pycasbin": (FALSE, "file under node_modules/.../node-gyp/: no __init__.py and a hyphenated folder, so it cannot be imported; read because egg-info top_level.txt names node_modules"),
    "pycurl": (REAL, "curl-config at install"),
    "pydicom": (REAL, "examples/__init__.py downloads data at import"),
    "pygit2": (REAL, "build probe at install"),
    "pyscreeze": (REAL, "which gnome-screenshot / scrot at import"),
    "quack_kernels": (REAL, "nvidia-smi at import"),
    "rasterio": (REAL, "gdal-config at install"),
    "safe_pysha3": (FALSE, "subprocess in a 'test' setup command; pip install never runs it"),
    "stringzilla": (REAL, "build backend runs the compiler at install"),
    "suds_community": (REAL, "exec(compile(...)) in setup.py"),
    "svgwrite": (REAL, "exec of its version line at install"),
    "uamqp": (REAL, "cmake at install"),
    "versioneer": (REAL, "exec at install and at import of its installer"),
    "webob": (REAL, "exec at module level in compat.py"),
    "aligntune": (REAL, "bundles unsloth: network, process and exec at import"),
    "autotimm": (REAL, "update check over the network at import"),
    "duckframework": (REAL, "os.system (Windows icacls) at module level"),
    "edx_rest_api_client": (REAL, "DNS lookup at module level for the user agent"),
    "iai_pme": (REAL, "npm ci and npm run build at install"),
    "jabs_behavior_classifier": (REAL, "265 of 266 RECORD hashes do not match, confirmed with a separate check; a packaging fault, not malice"),
    "malva": (REAL, "liburing probe at install"),
    "matid": (REAL, "shipped scripts call urlopen at module level; clang probe at install"),
    "mri_nufft": (REAL, "bart probe with subprocess at import"),
    "pymol_open_source_whl": (REAL, "make_simple.py shipped in the package runs os.system at module level"),
    "qiskit_aer_gpu": (REAL, "git version at import"),
    "wmglobalqueue": (FALSE, "os.system in a 'clean' setup command; pip install never runs it"),
}


def note(sample):
    name = sample.split("/", 1)[1]
    hits = [k for k in NOTES if name.startswith(k)]
    return NOTES[max(hits, key=len)]


lst, bkt, out = sys.argv[1:4]
results = {json.loads(l)["sample"]: json.loads(l) for l in gzip.open(bkt, "rt")}
rows = []
for s in (l.strip() for l in open(lst) if l.strip()):
    r = results[s]
    cat, why = note(s)
    rows.append({"sample": s, "rules": " ".join(sorted({f["rule_id"] for f in r["findings"] if f["severity"] != "info"})),
                 "verdict": cat, "note": why})
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
print(collections.Counter(r["verdict"] for r in rows), collections.Counter(r["sample"][:2] for r in rows))
