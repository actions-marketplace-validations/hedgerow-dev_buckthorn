import pytest

from buckthorn.scan import scan_wheel


def _rules(findings):
    return sorted(f.rule_id for f in findings)


@pytest.mark.parametrize(
    "member",
    [
        "sitecustomize.py",
        "usercustomize.py",
        "sitecustomize/__init__.py",
        "sitecustomize.pyc",
        "sitecustomize.cpython-312-darwin.so",
        "pkg-1.0.data/purelib/sitecustomize.py",
        "./sitecustomize.py",
    ],
)
def test_shipping_a_startup_module_fires(make_wheel, member):
    findings = scan_wheel(
        make_wheel({member: "x = 1\n"}, "pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl")
    )
    (start,) = [f for f in findings if f.rule_id == "BKT-START-001"]
    assert start.severity.value == "high"
    # A sourceless sitecustomize.pyc is also bytecode nobody can read (BKT-HIDE-003).
    assert set(_rules(findings)) <= {"BKT-START-001", "BKT-HIDE-003"}


def test_startup_name_inside_a_package_is_fine(make_wheel):
    assert scan_wheel(make_wheel({"pkg/sitecustomize.py": "x = 1\n"})) == []


def _entry_points(scripts: str, section: str = "console_scripts") -> dict[str, str]:
    return {"pkg-1.0.dist-info/entry_points.txt": f"[{section}]\n{scripts}\n"}


@pytest.mark.parametrize("command", ["python", "python3", "python3.12", "pip", "git", "ssh", "Git"])
def test_console_script_shadowing_a_common_command_fires(make_wheel, command):
    findings = scan_wheel(make_wheel(_entry_points(f"{command} = evil:main")))
    assert _rules(findings) == ["BKT-SCRIPT-001"]


def test_gui_scripts_count_too(make_wheel):
    findings = scan_wheel(make_wheel(_entry_points("ssh = evil:main", "gui_scripts")))
    assert _rules(findings) == ["BKT-SCRIPT-001"]


def test_plain_script_in_data_scripts_counts(make_wheel):
    findings = scan_wheel(make_wheel({"pkg-1.0.data/scripts/git": "#!/bin/sh\n"}))
    assert _rules(findings) == ["BKT-SCRIPT-001"]


def test_ordinary_console_script_is_clean(make_wheel):
    assert scan_wheel(make_wheel(_entry_points("evil-cli = evil:main"))) == []


def test_pip_shipping_pip_is_clean(make_wheel):
    members = {"pip-24.0.dist-info/entry_points.txt": "[console_scripts]\npip = a:b\npip3 = a:b\n"}
    assert scan_wheel(make_wheel(members, "pip-24.0-py3-none-any.whl")) == []


def test_other_entry_point_groups_are_ignored(make_wheel):
    assert scan_wheel(make_wheel(_entry_points("python = evil:plugin", "evil.plugins"))) == []


def test_unparsable_entry_points_is_not_verified(make_wheel):
    findings = scan_wheel(make_wheel({"pkg-1.0.dist-info/entry_points.txt": "[console_scripts\n"}))
    assert _rules(findings) == ["BKT-SKIP-003"]
