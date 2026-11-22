import re
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _ids(text: str) -> set[str]:
    return set(re.findall(r"BKT-[A-Z]+-\d{3}", text))


def test_every_rule_in_the_code_is_documented():
    code = "".join(p.read_text() for p in (ROOT / "buckthorn").glob("*.py"))
    # Code-rule ids are templates: BKT-{when}-001 for INSTALL and IMPORT.
    numbers = re.findall(r'"BKT-\{when\}-(\d{3})"', code) + ["008"]
    assert numbers
    built = {f"BKT-{when}-{n}" for when in ("INSTALL", "IMPORT", "HF") for n in numbers}
    documented = _ids((ROOT / "docs" / "rules.md").read_text())
    assert (_ids(code) | built) - documented == set()


def test_server_json_names_the_release_version_everywhere():
    import json
    import tomllib

    release = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    server = json.loads((ROOT / "server.json").read_text())
    (package,) = server["packages"]
    values = [a["value"] for a in package["runtimeArguments"]]
    pins = [v.partition("==")[2] for v in values if "==" in v]
    assert [server["version"], package["version"], *pins] == [release] * 3
