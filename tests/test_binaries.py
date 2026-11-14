import struct

import pytest

from buckthorn.scan import scan_sdist, scan_wheel

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
FAT_MACHO = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 56
PE = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 16
JAVA_CLASS = b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + b"\x00" * 56

PURE = "pkg-1.0-py3-none-any.whl"
PLATFORM = "pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"


def _rules(findings):
    return sorted(f.rule_id for f in findings)


@pytest.mark.parametrize("member", ["pkg/_fast.so", "pkg/_fast.pyd", "pkg/lib.dll", "pkg/a.dylib"])
def test_native_code_in_a_pure_wheel_fires(make_wheel, member):
    findings = scan_wheel(make_wheel({member: ELF}, PURE))
    assert _rules(findings) == ["BKT-BIN-001"]


def test_native_code_in_a_platform_wheel_is_expected(make_wheel):
    assert (
        scan_wheel(make_wheel({"pkg/_fast.cpython-312-x86_64-linux-gnu.so": ELF}, PLATFORM)) == []
    )


@pytest.mark.parametrize("blob", [ELF, MACHO, FAT_MACHO, PE])
def test_executable_disguised_as_another_file_fires(make_wheel, blob):
    # Any wheel, pure or not: an executable named like data is hiding.
    for wheel_name in (PURE, PLATFORM):
        findings = scan_wheel(make_wheel({"pkg/logo.png": blob}, wheel_name))
        assert _rules(findings) == ["BKT-BIN-002"], wheel_name


def test_java_class_file_is_not_a_fat_binary(make_wheel):
    assert scan_wheel(make_wheel({"pkg/A.class": JAVA_CLASS}, PURE)) == []


def test_ordinary_files_are_clean(make_wheel):
    assert (
        scan_wheel(make_wheel({"pkg/__init__.py": "x = 1\n", "pkg/MZ.txt": "MZ hello"}, PURE)) == []
    )


def test_standalone_executable_in_a_pure_wheel_is_an_info_note(make_wheel):
    # pip and setuptools ship Windows launcher .exe files in pure wheels.
    findings = scan_wheel(make_wheel({"pkg/cli-64.exe": PE, "pkg/helper": ELF}, PURE))
    assert _rules(findings) == ["BKT-BIN-003", "BKT-BIN-003"]
    assert {f.severity.value for f in findings} == {"info"}


def test_standalone_executable_in_a_platform_wheel_is_expected(make_wheel):
    assert scan_wheel(make_wheel({"pkg/bin/ffmpeg": ELF}, PLATFORM)) == []


# An sdist ships source: a binary in it is not built from what was read.
def test_native_code_in_an_sdist_fires(make_sdist):
    findings = scan_sdist(make_sdist({"pkg/_fast.so": ELF, "pkg/lib.dll": PE}))
    assert _rules(findings) == ["BKT-BIN-001", "BKT-BIN-001"]


def test_executable_disguised_in_an_sdist_fires(make_sdist):
    assert _rules(scan_sdist(make_sdist({"pkg/logo.png": PE}))) == ["BKT-BIN-002"]


def test_standalone_executable_in_an_sdist_is_an_info_note(make_sdist):
    findings = scan_sdist(make_sdist({"pkg/Helper.exe": PE}))
    assert [(f.rule_id, f.severity.value) for f in findings] == [("BKT-BIN-003", "info")]
    assert "sdist" in findings[0].message


def test_a_file_only_named_like_a_library_in_an_sdist_is_not_native_code(make_sdist):
    # numpy vendors meson, whose "test cases" hold empty libboost_regex.so.0.1.0 stand-ins.
    members = {"vendored/test cases/lib/libx.so.0.1.0": b"", "pkg/stub.dll": b""}
    assert scan_sdist(make_sdist(members)) == []


def test_a_library_that_is_not_a_plain_binary_in_an_sdist_still_counts(make_sdist):
    # Found by review: an encrypted or packed .so, decoded at install, is still native code.
    findings = scan_sdist(make_sdist({"pkg/_core.so": b"\x93\x11packed"}))
    assert _rules(findings) == ["BKT-BIN-001"]


def test_binaries_in_sdist_test_folders_are_not_read(make_sdist):
    # Parser fixtures (an ELF reader's test files) are not installed.
    members = {"tests/data/x.so": ELF, "pkg/tests/fake.png": PE}
    assert scan_sdist(make_sdist(members)) == []
