
# --- Buckthorn detonation: log risky events from every Python process (guest only) ---
def _det_audit():
    import json
    import os
    import sys
    import time
    try:
        log = open("/var/log/det/audit.log", "a", buffering=1)
    except OSError:
        return
    watch = ("socket.", "subprocess.", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork",
             "urllib.", "http.client", "ftplib", "smtplib", "shutil.", "os.remove", "os.rename", "os.chmod",
             "os.listdir", "os.scandir", "glob.", "ctypes.", "exec", "compile", "open", "import")
    stage = os.environ.get("DET_STAGE", "?")
    count = [0]
    noisy = ("/usr/lib/python", "/usr/local/lib/python", "/proc/", "/dev/")

    def hook(event, args):
        if count[0] > 20000 or not event.startswith(watch):
            return
        if event in ("open", "import", "compile", "exec"):
            first = str(args[0]) if args else ""
            if event == "open":
                mode = str(args[1]) if len(args) > 1 else "r"
                if not any(c in mode for c in "wax+") and first.startswith(noisy):
                    return
            elif event == "import" and not first.startswith(("socket", "subprocess", "urllib", "http", "ctypes", "base64", "marshal", "zlib", "requests")):
                return
            elif event in ("compile", "exec"):
                pass
        count[0] += 1
        log.write(json.dumps([round(time.time(), 3), stage, os.getpid(), event, repr(args)[:300]]) + "\n")

    sys.addaudithook(hook)


_det_audit()
del _det_audit
