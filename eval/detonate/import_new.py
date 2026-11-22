"""Import every top-level module the newly installed distribution provides (guest only)."""
import importlib
import importlib.metadata as md

BASE = {"pip", "setuptools", "wheel"}
for dist in md.distributions():
    if (dist.metadata["Name"] or "").lower() in BASE:
        continue
    names = set((dist.read_text("top_level.txt") or "").split())
    for f in dist.files or []:
        part = str(f).split("/")[0]
        if part.endswith(".py"):
            names.add(part[:-3])
        elif "." not in part and not part.endswith((".dist-info", ".egg-info")) and part != "__pycache__":
            names.add(part)
    for name in sorted(n for n in names if n.isidentifier()):
        try:
            importlib.import_module(name)
            print("imported", name)
        except BaseException as e:  # noqa: BLE001 - record how the import ended
            print("import", name, "raised", repr(e)[:200])
