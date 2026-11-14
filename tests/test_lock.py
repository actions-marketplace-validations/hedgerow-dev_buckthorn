import hashlib
import json

import pytest

from buckthorn import lock

HOST = "https://files.pythonhosted.org/packages/aa/bb"
SHADOW = "import sys; sys.modules['collections'] = None\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakePyPI:
    """Serves artifact bytes by URL and the JSON API by name and version; counts calls."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.releases: dict[tuple[str, str], list[dict]] = {}
        self.calls: list[str] = []

    def add(self, name: str, version: str, filename: str, data: bytes) -> str:
        url = f"{HOST}/{filename}"
        self.files[url] = data
        entry = {"filename": filename, "url": url, "digests": {"sha256": _sha(data)}}
        self.releases.setdefault((name, version), []).append(entry)
        return url

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.calls.append(url)
        for (name, version), entries in self.releases.items():
            if url == f"https://pypi.org/pypi/{name}/{version}/json":
                return json.dumps({"urls": entries}).encode()
        if url in self.files:
            return self.files[url]
        raise lock.FetchError(f"404 {url}")


@pytest.fixture
def pypi():
    return FakePyPI()


@pytest.fixture
def wheel_bytes(make_wheel):
    def _bytes(members, name="pkg-1.0-py3-none-any.whl") -> bytes:
        return make_wheel(members, name).read_bytes()

    return _bytes


# Parsing


def test_parse_requirements_with_hashes(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text(
        "# comment\n"
        "--index-url https://pypi.org/simple\n"
        "requests==2.32.3 \\\n"
        "    --hash=sha256:aaa \\\n"
        "    --hash=sha256:bbb\n"
        "Click[extra]==8.1.7 ; python_version >= '3.8' --hash=sha256:ccc  # trailing\n"
    )
    pins = lock.parse(path)
    assert [(p.name, p.version, [f.sha256 for f in p.files], p.problem) for p in pins] == [
        ("requests", "2.32.3", ["aaa", "bbb"], None),
        ("Click", "8.1.7", ["ccc"], None),
    ]


@pytest.mark.parametrize(
    "line",
    [
        "requests>=2.0 --hash=sha256:aaa",
        "requests==2.32.3",
        "-e ./local",
        "-r other.txt",
        "git+https://github.com/x/y",
    ],
)
def test_requirements_lines_that_cannot_be_checked_say_so(tmp_path, line):
    path = tmp_path / "requirements.txt"
    path.write_text(line + "\n")
    (pin,) = lock.parse(path)
    assert pin.problem


def test_parse_uv_lock(tmp_path):
    path = tmp_path / "uv.lock"
    path.write_text(
        "version = 1\n"
        "[[package]]\n"
        'name = "anyio"\nversion = "4.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        f'sdist = {{ url = "{HOST}/anyio-4.0.tar.gz", hash = "sha256:aaa", size = 1 }}\n'
        f'wheels = [{{ url = "{HOST}/anyio-4.0-py3-none-any.whl", hash = "sha256:bbb" }}]\n'
        "[[package]]\n"
        'name = "mine"\nversion = "0.1"\nsource = { editable = "." }\n'
    )
    pins = lock.parse(path)
    assert [(p.name, [(f.filename, f.sha256) for f in p.files]) for p in pins] == [
        ("anyio", [("anyio-4.0.tar.gz", "aaa"), ("anyio-4.0-py3-none-any.whl", "bbb")]),
        ("mine", []),
    ]
    # The project itself is not a dependency to check.
    assert pins[1].problem is None
    assert pins[1].skip


def test_uv_lock_package_from_another_index_cannot_be_checked(tmp_path):
    path = tmp_path / "uv.lock"
    path.write_text(
        "version = 1\n[[package]]\n"
        'name = "x"\nversion = "1"\nsource = { registry = "https://example.com/simple" }\n'
        'wheels = [{ url = "https://example.com/x-1-py3-none-any.whl", hash = "sha256:a" }]\n'
    )
    (pin,) = lock.parse(path)
    assert "not on PyPI" in pin.problem


def test_parse_poetry_lock(tmp_path):
    path = tmp_path / "poetry.lock"
    path.write_text(
        "[[package]]\n"
        'name = "six"\nversion = "1.16.0"\n'
        'files = [{ file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:aaa" }]\n'
        '[metadata]\nlock-version = "2.0"\n'
    )
    (pin,) = lock.parse(path)
    assert [(f.filename, f.sha256, f.url) for f in pin.files] == [
        ("six-1.16.0-py2.py3-none-any.whl", "aaa", None)
    ]


def test_unknown_lockfile_name_is_an_error(tmp_path):
    path = tmp_path / "Pipfile.lock"
    path.write_text("{}")
    with pytest.raises(ValueError):
        lock.parse(path)


# Fetching and scanning


def test_check_scans_each_pinned_artifact(tmp_path, pypi, wheel_bytes):
    data = wheel_bytes({"pkg.pth": SHADOW})
    pypi.add("pkg", "1.0", "pkg-1.0-py3-none-any.whl", data)
    req = tmp_path / "requirements.txt"
    req.write_text(f"pkg==1.0 --hash=sha256:{_sha(data)}\n")
    (result,) = lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    assert result.path == "pkg-1.0-py3-none-any.whl"
    assert result.sha256 == _sha(data)
    assert result.verdict == "flagged"


def test_check_uses_urls_from_uv_lock_without_the_json_api(tmp_path, pypi, wheel_bytes):
    data = wheel_bytes({"pkg/__init__.py": "x = 1\n"})
    url = pypi.add("pkg", "1.0", "pkg-1.0-py3-none-any.whl", data)
    path = tmp_path / "uv.lock"
    path.write_text(
        "version = 1\n[[package]]\n"
        'name = "pkg"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\n'
        f'wheels = [{{ url = "{url}", hash = "sha256:{_sha(data)}" }}]\n'
    )
    (result,) = lock.check(path, fetch=pypi, cache_dir=tmp_path / "cache")
    assert result.verdict == "clean"
    assert pypi.calls == [url]


def test_hash_mismatch_is_flagged_and_not_scanned(tmp_path, pypi, wheel_bytes):
    data = wheel_bytes({"pkg/__init__.py": "x = 1\n"})
    pypi.add("pkg", "1.0", "pkg-1.0-py3-none-any.whl", data)
    pypi.releases[("pkg", "1.0")][0]["digests"]["sha256"] = "0" * 64  # index says one thing
    req = tmp_path / "requirements.txt"
    req.write_text(f"pkg==1.0 --hash=sha256:{'0' * 64}\n")
    (result,) = lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    assert [f.rule_id for f in result.findings] == ["BKT-LOCK-001"]
    assert result.verdict == "flagged"


def test_pinned_hash_not_on_pypi_is_not_verified(tmp_path, pypi, wheel_bytes):
    pypi.add("pkg", "1.0", "pkg-1.0-py3-none-any.whl", wheel_bytes({"pkg/a.py": ""}))
    req = tmp_path / "requirements.txt"
    req.write_text(f"pkg==1.0 --hash=sha256:{'1' * 64}\n")
    (result,) = lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    assert [f.rule_id for f in result.findings] == ["BKT-LOCK-002"]
    assert result.verdict == "not_verified"


def test_fetch_failure_is_not_verified(tmp_path, pypi):
    req = tmp_path / "requirements.txt"
    req.write_text(f"gone==1.0 --hash=sha256:{'1' * 64}\n")
    (result,) = lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    assert result.verdict == "not_verified"


def test_problem_pins_are_not_verified(tmp_path, pypi):
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2\n")
    (result,) = lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    assert result.path == "requests>=2"
    assert result.verdict == "not_verified"


def test_url_off_pypi_is_refused_before_fetching(tmp_path, pypi):
    path = tmp_path / "uv.lock"
    path.write_text(
        "version = 1\n[[package]]\n"
        'name = "pkg"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\n'
        'wheels = [{ url = "https://evil.example/pkg-1.0-py3-none-any.whl", hash = "sha256:a" }]\n'
    )
    (result,) = lock.check(path, fetch=pypi, cache_dir=tmp_path / "cache")
    assert result.verdict == "not_verified"
    assert pypi.calls == []


@pytest.mark.parametrize("filename", ["../evil-1.0-py3-none-any.whl", "pkg-1.0.exe", "a/b.whl"])
def test_odd_file_names_are_refused(tmp_path, pypi, filename):
    path = tmp_path / "poetry.lock"
    path.write_text(
        '[[package]]\nname = "pkg"\nversion = "1.0"\n'
        f'files = [{{ file = "{filename}", hash = "sha256:a" }}]\n'
    )
    (result,) = lock.check(path, fetch=pypi, cache_dir=tmp_path / "cache")
    assert result.verdict == "not_verified"
    assert not any(p.suffix == ".exe" for p in (tmp_path / "cache").rglob("*"))


def test_cache_means_one_download(tmp_path, pypi, wheel_bytes):
    data = wheel_bytes({"pkg/__init__.py": "x = 1\n"})
    pypi.add("pkg", "1.0", "pkg-1.0-py3-none-any.whl", data)
    req = tmp_path / "requirements.txt"
    req.write_text(f"pkg==1.0 --hash=sha256:{_sha(data)}\n")
    lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    downloads = [c for c in pypi.calls if c.startswith(HOST)]
    lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    assert [c for c in pypi.calls if c.startswith(HOST)] == downloads


def test_tampered_cache_entry_is_fetched_again(tmp_path, pypi, wheel_bytes):
    data = wheel_bytes({"pkg/__init__.py": "x = 1\n"})
    pypi.add("pkg", "1.0", "pkg-1.0-py3-none-any.whl", data)
    req = tmp_path / "requirements.txt"
    req.write_text(f"pkg==1.0 --hash=sha256:{_sha(data)}\n")
    lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    (cached,) = (tmp_path / "cache").rglob("*.whl")
    cached.write_bytes(b"swapped")
    (result,) = lock.check(req, fetch=pypi, cache_dir=tmp_path / "cache")
    assert result.verdict == "clean"


# Choosing what this machine would install


def _here_tag() -> str:
    from packaging.tags import sys_tags

    tag = next(iter(sys_tags()))
    return f"{tag.interpreter}-{tag.abi}-{tag.platform}"


def _uv_lock(path, files):
    rows = ", ".join(f'{{ url = "{HOST}/{name}", hash = "sha256:{sha}" }}' for name, sha in files)
    path.write_text(
        "version = 1\n[[package]]\n"
        'name = "pkg"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\n'
        f"wheels = [{rows}]\n"
    )
    return path


def test_default_checks_only_the_wheel_this_machine_would_install(tmp_path, pypi, wheel_bytes):
    here = f"pkg-1.0-{_here_tag()}.whl"
    other = "pkg-1.0-cp312-cp312-win_amd64.whl"
    pure = "pkg-1.0-py3-none-any.whl"
    files = []
    for name in (other, pure, here):
        data = wheel_bytes({"pkg/__init__.py": "x = 1\n"}, name)
        pypi.add("pkg", "1.0", name, data)
        files.append((name, _sha(data)))
    path = _uv_lock(tmp_path / "uv.lock", files)
    assert [r.path for r in lock.check(path, fetch=pypi)] == [here]
    assert sorted(r.path for r in lock.check(path, fetch=pypi, all_files=True)) == sorted(
        [other, pure, here]
    )


def test_falls_back_to_the_sdist_when_no_wheel_fits(tmp_path, pypi, wheel_bytes, make_sdist):
    sdist = make_sdist({"setup.py": "from setuptools import setup\nsetup()\n"}).read_bytes()
    wheel = wheel_bytes({"pkg/__init__.py": ""}, "pkg-1.0-cp312-cp312-win_amd64.whl")
    pypi.add("pkg", "1.0", "pkg-1.0.tar.gz", sdist)
    pypi.add("pkg", "1.0", "pkg-1.0-cp312-cp312-win_amd64.whl", wheel)
    req = tmp_path / "requirements.txt"
    req.write_text(f"pkg==1.0 --hash=sha256:{_sha(sdist)} --hash=sha256:{_sha(wheel)}\n")
    assert [r.path for r in lock.check(req, fetch=pypi)] == ["pkg-1.0.tar.gz"]


def test_nothing_installable_here_is_a_note_not_a_failure(tmp_path, pypi, wheel_bytes):
    data = wheel_bytes({"pkg/__init__.py": ""}, "pkg-1.0-cp312-cp312-win_amd64.whl")
    pypi.add("pkg", "1.0", "pkg-1.0-cp312-cp312-win_amd64.whl", data)
    path = _uv_lock(tmp_path / "uv.lock", [("pkg-1.0-cp312-cp312-win_amd64.whl", _sha(data))])
    (result,) = lock.check(path, fetch=pypi)
    assert [f.rule_id for f in result.findings] == ["BKT-LOCK-003"]
    assert result.verdict == "clean"
    assert [c for c in pypi.calls if c.startswith(HOST)] == []
