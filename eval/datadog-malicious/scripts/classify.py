import collections
import csv
import json
import re

rows = [json.loads(l) for l in open("missed.jsonl")]
IGN = {
    "open",
    "threading.Thread",
    "threading.Thread.start",
    "threading.Lock",
    "platform.system",
    "platform.platform",
    "platform.node",
    "platform.machine",
    "platform.python_version",
    "platform.release",
    "compile",
}
HAND = {  # read by hand: sample-name fragment -> (reason, fix)
    "kube-health-tools-v1.0.8.zip": (
        "wheel: payload only in main(), run from the console script or python -m",
        "scope",
    ),
    "kube-health-tools-v1.0.9.zip": (
        "wheel: payload only in main(), run from the console script or python -m",
        "scope",
    ),
    "kube-health-tools-v1.0.13.zip": (
        "wheel: payload moved into a compiled extension (__init__.cpython-311-x86_64-linux-gnu.so); native code is not read",
        "none",
    ),
    "kube-health-tools-v1.0.14.zip": (
        "wheel: payload moved into a compiled extension (__init__.cpython-311-x86_64-linux-gnu.so); native code is not read",
        "none",
    ),
    "ultralytics-v8.3.4": (
        "compromised wheel: miner launched by safe_run() when a YOLO model is created; runtime code, not install or import",
        "scope",
    ),
    "lightning-v2.6.": (
        "compromised wheel: __init__.py starts threading.Thread(target=_run_runtime) at import, which runs _runtime/start.py",
        "G2",
    ),
    "litellm-v1.82.7": (
        "compromised sdist: proxy/proxy_server.py decodes a base64 blob to a temp file and runs it with subprocess at module level; sdist package code is not read",
        "G1",
    ),
    "telnyx-v4.87": (
        "compromised wheel: _client.py calls setup() and FetchAudio() at module level; they download a payload, drop it in the Windows Startup folder (path base64-encoded) and run python -c exec(b64decode(...))",
        "G2",
    ),
    "mistralai-v2.4.6": (
        "compromised wheel: client/__init__.py calls _run_background_task() at module level, which runs Popen",
        "G2",
    ),
    "kube-health-tools-v1.0.": (
        "wheel: __init__.py starts threading.Thread(target=_go) at import; _go downloads and runs a binary (URL Caesar-shifted)",
        "G2",
    ),
    "kube-health-tools-v2.0.0": (
        "wheel: payload moved into a compiled extension (__init__.cpython-311-x86_64-linux-gnu.so); native code is not read",
        "none",
    ),
    "kube-health-tools-v1.0.1": (
        "wheel: payload moved into a compiled extension (__init__.cpython-311-x86_64-linux-gnu.so); native code is not read",
        "none",
    ),
    "memoryos-v2.0.34": (
        "compromised wheel: memos/_initial_ci_delivery.py is a CI-time downloader, not run at install or import",
        "scope",
    ),
    "pypackscraper": (
        "wheel: obfuscated payload is assembled into a variable but never executed in this sample (inert)",
        "inert",
    ),
    "example-package-sthnck": (
        'test package: exec("cat /etc/passwd") parses as division, does nothing; or empty git checkout (inert)',
        "inert",
    ),
    "security-util": (
        "setup.py install command opens a TLS socket via ssl.wrap_socket(...).connect/send to exfiltrate host and user; the wrapped socket is not resolved as a socket",
        "G4",
    ),
    "sagetest": (
        "setup.py install command clones a GitHub repo with GitPython into the Windows Startup folder; the path is an f-string so the start-up regex never sees it",
        "G3+G5",
    ),
    "testinglmao123": (
        "setup.py only; payload expected from GitPython clone family (sagetest), not present in this sample",
        "none",
    ),
    "pycryptoconf": (
        "oscrypto clone campaign: setup.py only copies LICENSE (benign); any payload sits in package functions such as load(), not run at install or import",
        "scope",
    ),
    "pycryptoenv": (
        "oscrypto clone campaign: setup.py only copies LICENSE (benign); any payload sits in package functions such as load(), not run at install or import",
        "scope",
    ),
    "quasarlib": (
        "oscrypto clone campaign: __init__.load() runs subprocess when called; setup.py only copies LICENSE",
        "scope",
    ),
    "swapmempool": (
        "oscrypto clone campaign: setup.py only copies LICENSE (benign); any payload sits in package functions, not run at install or import",
        "scope",
    ),
    "python-ledgercommon": (
        "wheel ships the malicious setup.py as a package module; its install command never runs from a wheel (inert in this form; the sdist form would run it)",
        "inert",
    ),
    "0wneg": ("known proof-of-concept: setup.py writes a marker file in the home folder", "inert"),
    "consolecmds": (
        "sdist package module consolecmds/setup.py (not the build script) downloads with curl and hides files; sdist package code is not read",
        "G1+G2",
    ),
    "pdf2doc-v0.3.9": (
        "setup.py reaches modules through __import__ with names built at run time; not fully read by hand",
        "G7",
    ),
    "aiogram-types-v3-v3.1.0": (
        "setup.py decodes base64 strings in a helper, no exec seen; not fully read by hand",
        "review",
    ),
    "s3transfer-sl": (
        "payload is in the project source tree setup.py captured beside the wheel; the wheel itself carries none",
        "none",
    ),
    "set-utils-v1.1.0": (
        "payload is in the project source tree setup.py captured beside the wheel; the wheel itself carries none",
        "none",
    ),
    "python3-flask": (
        "setup.py install writes an obfuscated browser extension under %APPDATA% and Start Menu shortcuts, and runs pip via pip._internal.main; paths built from getenv",
        "G3+G5",
    ),
    "2022-11-07-": (
        "setup.py install writes an obfuscated browser extension under %APPDATA% and Start Menu shortcuts, and runs pip via pip._internal.main; paths built from getenv",
        "G3+G5",
    ),
    "instacart-roulette": (
        "setup.py exfiltrates user, host and cwd by DNS lookup of a base64 subdomain; socket.gethostbyname is reached through importlib.import_module and getattr with a split name",
        "G7",
    ),
    "random-security-test-pkg": (
        "same as instacart-roulette: DNS exfiltration through importlib + getattr with computed names",
        "G7",
    ),
    "botoceor": (
        "setup.py install appends a shell payload to ~/.profile; path and payload built from chr() lists and a Caesar shift",
        "G3",
    ),
    "setuptolos": (
        "same family as botoceor: install appends an obfuscated payload to ~/.profile",
        "G3",
    ),
    "bo3to": ("same family as botoceor: install appends an obfuscated payload to ~/.profile", "G3"),
    "tiketoken": (
        'setup.py install runs "from main import main; main()"; main.py sends host, user and cwd to an OAST URL from inside main()',
        "G6",
    ),
    "easydicts": (
        "setup.py install calls main() from a sibling module that collects MACs and calls OAST URLs",
        "G6",
    ),
    "cryptograohy": (
        "setup.py install imports and runs a dependency (pyprettifier) listed in install_requires; the payload is in the dependency",
        "dep",
    ),
    "crytic-compilers": (
        "setup.py calls crytic_compile.install.start() at top level; the imported module is not in this sample",
        "G6",
    ),
    "artifact-lab-3-package-a18ff5d9": (
        "setup.py builds a POST of os.environ but never sends it (inert)",
        "inert",
    ),
    "reverse-shell-v0.5": (
        "webhook notice only runs under if __name__ == '__main__' (inert at import)",
        "inert",
    ),
    "reverse-shell-v0.1": (
        "sdist package module reverse_shell.py calls connect() (reverse shell to localhost) at module level; sdist package code is not read",
        "G1",
    ),
    "reverse-shell-v1.0": (
        "setup.py does not parse (stray indent): reported not_verified, correct; pip would also fail",
        "ok",
    ),
    "salamus": ("typosquat research probe: writes a text file in /tmp at install", "inert"),
    "usvr-agent": ("awareness package: install aborts with a message", "inert"),
    "usar-agent": ("awareness package: install aborts with a message", "inert"),
    "dfdfdfdfhhh": ("install command only prints", "inert"),
    "deepseekai": (
        "wheel: impostor package; main() exfiltrates id/hostname, run only from the console script",
        "scope",
    ),
    "vermillion-v0.5": (
        "sdist ships vermillion/bot.exe; executables in sdists are not checked",
        "G8",
    ),
    "randomized": (
        "sdist package module rand.py: exec(b64decode(...)) at import; sdist package code is not read",
        "G1",
    ),
    "fijiwashere": (
        "sdist package __init__ steals Discord tokens; sdist package code is not read (and does not parse)",
        "G1",
    ),
}
FIX = {
    "G1": "Read sdist package modules with the import and hidden-code rules (they become installed modules).",
    "G2": "Follow module-level calls into functions defined in the same module, and thread/process targets.",
    "G3": "Fold simple string building (f-strings, joins, chr lists, constant base64) before matching start-up and credential paths; flag install-time writes outside the build tree.",
    "G4": "Treat ssl wrap_socket(...) of a socket as a socket.",
    "G5": "Add GitPython clone and pip._internal.main to the network calls.",
    "G6": "Follow install-time calls into functions of local modules setup.py imports.",
    "G7": "Flag install code that reaches a function through importlib + getattr with a computed name.",
    "G8": "Check sdists for shipped executables (BKT-BIN rules).",
}


def is_setup(p):
    return p.split("/")[-1] == "setup.py" and p.count("/") <= 1


def classify(r):
    s = r["sample"]
    for k, (why, fix) in HAND.items():
        if k in s:
            return "hand", why, fix
    setup_imports = set()
    for f in r["files"]:
        if is_setup(f["path"]):
            setup_imports.update(f.get("imports") or [])
    setup = []
    top = []
    via = []
    fn = []
    local_install = []
    for f in r["files"]:
        p = f["path"]
        if f.get("other"):
            continue
        mod = p.split("/")[0].removesuffix(".py")
        for c in f.get("calls", []):
            name, where = c.split("@", 1)
            if name in IGN:
                continue
            if is_setup(p) or p.endswith(".pth"):
                setup.append(c)
            elif r["kind"] != "wheel" and mod in setup_imports:
                local_install.append(c)
            elif where == "TOP":
                top.append(name)
            elif where.startswith("TOP-via"):
                via.append(name)
            else:
                fn.append(name)
    ep = any(f.get("entry_points") for f in r["files"]) or any(
        f["path"].endswith("entry_points.txt") for f in r["files"]
    )
    other = [f["path"] for f in r["files"] if f.get("other")]
    bins = [p for p in other if re.search(r"\.(exe|dll|so|pyd|scr|msi)$", p, re.I)]
    pe = any("parse_error" in f for f in r["files"])
    deps = [x for f in r["files"] for x in (f.get("requires") or [])] + [
        f.get("install_requires") or "" for f in r["files"]
    ]
    if r["verdict"] == "not_verified":
        return (
            "not_verified",
            "a file did not parse (BKT-SKIP-003); reported not_verified, which is correct",
            "ok",
        )
    if local_install:
        return (
            "install_via_local_module",
            "setup.py imports a local module whose functions make risky calls ("
            + ", ".join(sorted(set(x.split("@")[0] for x in local_install))[:4])
            + ")",
            "G6",
        )
    if setup:
        return (
            "install_code_missed",
            "setup.py has risky calls Buckthorn did not report ("
            + ", ".join(sorted(set(setup))[:4])
            + "); not read by hand",
            "G3/G6/G7",
        )
    if r["kind"] != "wheel" and (top or via or pe):
        return (
            "sdist_import_time",
            "sdist package module runs "
            + ", ".join(sorted(set(top + via))[:4] or ["code that does not parse"])
            + " at import; sdist package code is not read",
            "G1" + ("+G2" if via and not top else ""),
        )
    if via:
        return (
            "import_via_local_function",
            "module-level code reaches "
            + ", ".join(sorted(set(via))[:4])
            + " through a function in the same module or a thread target",
            "G2",
        )
    if top:
        return (
            "wheel_top_level_other",
            "top-level calls outside Buckthorn rule lists: " + ", ".join(sorted(set(top))[:4]),
            "review",
        )
    if fn:
        return (
            "function_only" + ("_entrypoint" if ep else ""),
            "risky calls only inside functions not reached at import or install ("
            + ", ".join(sorted(set(fn))[:4])
            + "); runs when the user calls the API or command",
            "scope",
        )
    if bins:
        return (
            "native_or_binary_payload",
            "no risky Python; ships " + ", ".join(bins[:2]),
            "G8" if r["kind"] != "wheel" else "none",
        )
    return (
        "no_payload_found",
        "no risky Python calls in the sample: placeholder, probe, dependency-only package, or payload outside the sample"
        + (" (depends on: " + "; ".join(d for d in deps if d)[:120] + ")" if any(deps) else ""),
        "none",
    )


out = []
for r in rows:
    b, why, fix = classify(r)
    out.append(
        {
            "sample": r["sample"],
            "artifact_kind": r["kind"],
            "verdict": r["verdict"],
            "rules": " ".join(r["rules"]),
            "bucket": b,
            "reason": why,
            "fix": fix,
        }
    )
with open("triage.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(out[0]))
    w.writeheader()
    w.writerows(sorted(out, key=lambda x: x["sample"]))
c = collections.Counter((o["bucket"], o["fix"]) for o in out)
for k, v in sorted(c.items(), key=lambda x: -x[1]):
    print(v, k)
print(len(out))
