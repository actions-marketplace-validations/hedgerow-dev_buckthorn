"""Offline tests for follow.py. Run: uv run pytest eval/live-watch"""

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import follow  # noqa: E402

T0 = "2026-11-23T17:00:00.000Z"


def _sha512(data: bytes) -> str:
    return base64.b64encode(hashlib.sha512(data).digest()).decode()


def test_npm_new_takes_versions_after_the_mark_oldest_first():
    doc = {
        "time": {
            "1.0.0": "2026-11-20T00:00:00.000Z",
            "1.1.0": "2026-11-23T17:05:00.000Z",
            "1.0.1": "2026-11-23T17:01:00.000Z",
            "modified": "2026-11-23T17:05:00.000Z",
        },
        "versions": {
            v: {"dist": {"tarball": f"{follow.NPM_HOST}p/-/p-{v}.tgz", "integrity": "sha512-QQ=="}}
            for v in ("1.0.0", "1.0.1", "1.1.0")
        },
    }
    assert [row[0] for row in follow.npm_new(doc, T0)] == ["1.0.1", "1.1.0"]
    assert follow.npm_new(doc, T0)[0][3] == "QQ=="
    assert follow.npm_new({"time": "x", "versions": []}, T0) == []  # odd shapes read as empty


def test_pypi_events_split_added_files_and_removals():
    events = [
        ["a", "1.0", 1, "new release", 10],
        ["a", "1.0", 1, "add py3 file a-1.0-py3-none-any.whl", 11],
        ["a", "1.0", 1, "add source file a-1.0.tar.gz", 12],
        ["b", "2.0", 2, "remove release", 13],
        ["c", "0.1", 3, "yank release", 14],
        ["d", "1", 4, "remove file d-1.tar.gz", 15],
        ["e", None, 5, "create", 16],
    ]
    added, removed = follow.pypi_events(events)
    assert [row[2] for row in added] == ["a-1.0-py3-none-any.whl", "a-1.0.tar.gz"]
    assert [row[2] for row in removed] == [
        "remove release",
        "yank release",
        "remove file d-1.tar.gz",
    ]


def test_safe_file_keeps_to_the_host_and_plain_names():
    npm = follow.NPM_HOST
    assert follow.safe_file(f"{npm}@s/p/-/p-1.0.0.tgz", npm) == "p-1.0.0.tgz"
    assert follow.safe_file("https://evil.example/p-1.0.0.tgz", npm) is None
    assert follow.safe_file(f"{npm}p/-/..%2f..%2fx.tgz", npm) is None
    assert follow.safe_file(f"{npm}p/-/.hidden.tgz", npm) is None
    assert follow.safe_file("http://registry.npmjs.org/p/-/p-1.tgz", npm) is None


def test_put_spools_only_files_whose_hash_matches(tmp_path):
    good, bad = b"tarball", b"tampered"
    watch = follow.Watch(tmp_path, fetch=lambda url, limit=0: good if "good" in url else bad)
    meta = {"eco": "npm", "name": "p", "version": "1"}
    watch.put(meta, f"{follow.NPM_HOST}p/-/good-1.tgz", follow.NPM_HOST, "sha512", _sha512(good))
    watch.put(meta, f"{follow.NPM_HOST}p/-/bad-1.tgz", follow.NPM_HOST, "sha512", _sha512(good))
    watch.put(meta, f"{follow.NPM_HOST}p/-/none-1.tgz", follow.NPM_HOST, "sha512", "")
    items = list((tmp_path / "spool").iterdir())
    assert len(items) == 1
    assert json.loads((items[0] / "meta.json").read_text())["file"] == "good-1.tgz"
    assert (items[0] / "good-1.tgz").read_bytes() == good
    why = [
        json.loads(line)["why"] for line in (tmp_path / "skipped.jsonl").read_text().splitlines()
    ]
    assert why == ["hash", "no hash"]


def test_npm_records_each_version_once(tmp_path):
    data = b"t"
    doc = {
        "time": {"1.0.1": "2026-11-23T17:01:00.000Z"},
        "versions": {
            "1.0.1": {
                "dist": {
                    "tarball": f"{follow.NPM_HOST}p/-/p-1.0.1.tgz",
                    "integrity": f"sha512-{_sha512(data)}",
                }
            }
        },
    }

    def fetch(url, limit=0):
        return json.dumps(doc).encode() if url.endswith("/p") else data

    watch = follow.Watch(tmp_path, fetch=fetch)
    watch.state = {"started": T0, "npm_after": {}}
    watch.npm("p")
    watch.npm("p")  # the package changes again, with no new version
    assert len(list((tmp_path / "spool").iterdir())) == 1


def test_a_failed_fetch_is_tried_again_later(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(follow.time, "time", lambda: clock[0])
    calls = []

    def fetch(url, limit=0):
        calls.append(url)
        if len(calls) == 1:
            raise follow.urllib.error.HTTPError(url, 404, "not yet", {}, None)
        return b"t"

    watch = follow.Watch(tmp_path, fetch=fetch)
    watch.state = {"later": []}
    url = f"{follow.NPM_HOST}p/-/p-1.tgz"
    watch.put({"eco": "npm"}, url, follow.NPM_HOST, "sha512", _sha512(b"t"))
    assert watch.due() == []  # not yet
    clock[0] += follow.LATER
    for args in watch.due():
        watch.put(*args)
    assert len(calls) == 2
    assert len(list((tmp_path / "spool").iterdir())) == 1
    assert watch.state["later"] == []


def test_a_fetch_that_keeps_failing_is_logged_as_skipped(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(follow.time, "time", lambda: clock[0])

    def fetch(url, limit=0):
        raise follow.urllib.error.HTTPError(url, 404, "gone", {}, None)

    watch = follow.Watch(tmp_path, fetch=fetch)
    watch.state = {"later": []}
    watch.put({"eco": "npm"}, f"{follow.NPM_HOST}p/-/p-1.tgz", follow.NPM_HOST, "sha512", "QQ==")
    for _ in range(5):
        clock[0] += 10 * follow.LATER
        for args in watch.due():
            watch.put(*args)
    why = [
        json.loads(line)["why"] for line in (tmp_path / "skipped.jsonl").read_text().splitlines()
    ]
    assert why == ["fetch 404"]


def test_pypi_sample_is_fixed_and_about_one_in_four():
    names = [f"pkg{i}" for i in range(4000)]
    picked = [n for n in names if follow.sampled(n, "1.0")]
    assert 800 < len(picked) < 1200
    assert picked == [n for n in names if follow.sampled(n, "1.0")]  # same every time
    assert follow.sampled("Some_Pkg", "1.0") == follow.sampled("some-pkg", "1.0")  # PEP 503 name


def test_pick_prefers_the_sdist_then_a_pure_wheel():
    def urls(*names):
        return [{"filename": n} for n in names]

    whl = "a-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    assert follow.pick(urls(whl, "a-1.0.tar.gz"))["filename"] == "a-1.0.tar.gz"
    assert follow.pick(urls(whl, "a-1.0-py3-none-any.whl"))["filename"] == "a-1.0-py3-none-any.whl"
    assert follow.pick(urls(whl))["filename"] == whl
    assert follow.pick([]) is None


def test_resolves_ipv4_only():
    import socket

    found = socket.getaddrinfo("localhost", 443, socket.AF_INET6, socket.SOCK_STREAM)
    assert found
    assert {family for family, *_ in found} == {socket.AF_INET}
