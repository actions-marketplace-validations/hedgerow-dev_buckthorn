"""Hugging Face remote code: what `from_pretrained(..., trust_remote_code=True)` runs.

transformers imports the .py files a model repo's `auto_map` names (in
config.json, tokenizer_config.json and the processor configs), plus the files
those import relatively, then builds the classes named there. Those files are
read here with the same rules as package code. Nothing is imported or run.

A repo is read from a local folder (a download, or a Hub cache snapshot) or
fetched from the Hub at one commit: only the JSON configs at its root and the
.py files they lead to, never weights. Network goes only to huggingface.co
over https; redirects are followed only to huggingface.co and hf.co hosts
(the Hub's file CDNs).
"""

from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path

from buckthorn.code import Hit, _deep_recursion, _is_main_check, analyse
from buckthorn.findings import Finding, Result, Severity
from buckthorn.lock import Fetch, FetchError
from buckthorn.scan import _CODE_RULES, MAX_SOURCE_BYTES

MAX_FILE_BYTES = MAX_SOURCE_BYTES
MAX_FILES = 100  # configs and code files read from one repo and the repos it names
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_API_BYTES = 16 * 1024 * 1024
GAP = "BKT-SKIP-006"
# Imported by from_pretrained whenever trust_remote_code is set and the repo has it
# (transformers 5.x generation/utils.py adjust_generation_fn), auto_map or not.
CUSTOM_GENERATE = "custom_generate/generate.py"

_REPO = re.compile(r"(?:[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_REVISION = re.compile(r"[\w.-]+(?:/[\w.-]+)*")
# transformers' own patterns for the files a remote module needs
# (dynamic_module_utils.get_relative_imports): it fetches and copies what these match.
_RELATIVE = re.compile(r"^\s*import\s+\.(\S+)\s*$|^\s*from\s+\.(\S+)\s+import", re.MULTILINE)
# Names transformers calls or reads on a model, config, tokenizer or processor while
# loading it: from_pretrained, __init__ and post_init of its base classes, followed
# through their own methods, in transformers 4.44.2 and 5.22.2. An auto_map class
# that defines one of these runs it at load. Plus to_dict and to_json_string, which
# the config's repr (logged at load) calls.
_HOOKS = frozenset(
    """
    __getstate__ __init__ _add_tokens _adjust_bias _adjust_missing_and_unexpected_keys
    _attn_implementation _autoset_attn_implementation
    _backward_compatibility_gradient_checkpointing _can_set_experts_implementation
    _check_and_adjust_attn_implementation _check_and_adjust_experts_implementation
    _check_and_enable_flash_attn_2 _check_and_enable_sdpa _convert_from_sentencepiece
    _convert_from_tiktoken _decode_special_floats _dict_from_json_file _finalize_model_loading
    _flash_attn_can_dispatch _flash_attn_import_error _flex_attn_can_dispatch _from_pretrained
    _get_arguments_from_pretrained _get_config_dict _get_dtype_plan _get_generation_defaults
    _get_is_as_tensor_fns _get_no_split_modules _grouped_mm_can_dispatch _init_weights
    _initialize_missing_keys _initialize_weights _load_and_finalize_distributed_pretrained_model
    _load_pretrained_model _load_tokenizer_from_pretrained _move_missing_keys_from_meta_to_device
    _patch_mistral_regex _sdpa_can_dispatch _set_default_torch_dtype _set_gradient_checkpointing
    _set_model_specific_special_tokens _set_token_in_kwargs _tie_encoder_decoder_weights
    _tie_or_clone_weights _update_total_vocab_size _update_trie activate_tracker add
    add_bos_token add_eos_token add_tokens added_tokens_decoder added_tokens_encoder
    adjust_generation_fn all_special_tokens all_special_tokens_extended apply base_model
    can_generate check_argument_for_proper_class convert_added_tokens convert_from_spm_model
    convert_to_native_format convert_to_tensors decoder enable_input_require_grads eval
    from_args_and_dict from_dict from_pretrained generation_config_class get_attributes
    get_buffer get_config_dict get_correct_attn_implementation
    get_correct_experts_implementation get_expanded_tied_weights_keys get_feature_extractor_dict
    get_image_processor_dict get_init_context get_input_embeddings get_output_embeddings
    get_parameter get_parameter_or_buffer get_possibly_dynamic_module get_processor_dict
    get_submodule get_vocab gradient_checkpointing_enable init_parallel_plans init_weights
    initialize_weights is_active is_custom_code is_remote_code items keys load_adapter
    load_tf_weights mark_tied_weights_as_initialized maybe_distribute_model model_input_names
    modules name_or_path named_buffers named_children named_modules named_non_persistent_buffers
    named_parameters num_labels parameters pop post_init prepare_distribute_model prune_heads
    set_use_kernels slow_tokenizer_class special_tokens_map_extended state_dict tie_weights
    train unused_input_names update update_post_processor use_kernels validate_init_kwargs
    vocab_size to_dict to_diff_dict to_json_string
    """.split()
)
# Calls that fetch code and run it, or fetch a file another call may run.
_RUNS_FETCHED = frozenset({"get_class_from_dynamic_module", "get_cached_module_file"})
_HUB_DOWNLOADS = frozenset({"hf_hub_download", "snapshot_download", "cached_file"})
_FILE_LOADERS = frozenset(
    {
        "importlib.util.spec_from_file_location",
        "importlib.machinery.SourceFileLoader",
        "runpy.run_path",
        "imp.load_source",
    }
)
_ANYWHERE = frozenset({"hidden", "encoded", "discord", "telegram"})

Read = Callable[[str], bytes]  # a repo file by its path; raises _Gap
Function = ast.FunctionDef | ast.AsyncFunctionDef


class _Gap(Exception):
    def __init__(self, message: str, rule: str = GAP) -> None:
        super().__init__(message)
        self.rule = rule


def parse_spec(spec: str) -> tuple[str, str | None]:
    """(repo id, revision or None) from org/name[@revision]. ValueError if malformed."""
    repo, sep, revision = spec.partition("@")
    if not _REPO.fullmatch(repo) or ".." in repo:
        raise ValueError("not a Hugging Face repo id (org/name, or org/name@commit)")
    if sep and not (_REVISION.fullmatch(revision) and ".." not in revision):
        raise ValueError("not a revision: give a commit id, branch or tag after @")
    return repo, revision if sep else None


def is_model_folder(path: Path) -> bool:
    names = ("config.json", "tokenizer_config.json", "preprocessor_config.json")
    return any((path / name).is_file() for name in names + ("processor_config.json",))


def scan_folder(path: Path) -> Result:
    """The remote code of a model repo on disk. Nothing is fetched."""
    findings, files, entries, others = _read_repo(*_folder_reader(path), "", [0, 0])
    for other in others:
        message = f"auto_map loads code from {other}, which a local scan does not fetch"
        findings.append(Finding(GAP, f"{message}: run buckthorn hf {other}", Severity.INFO, other))
        findings.append(_unpinned_other(other))
    return Result(str(path), "", findings + _check_code(files, entries))


def scan_repo(spec: str, fetch: Fetch | None = None) -> Result:
    """The remote code of a Hub repo at one commit. ValueError for a malformed spec."""
    fetch = fetch or fetch_url
    repo, revision = parse_spec(spec)
    try:
        sha, names, read = _hub_reader(repo, revision or "main", fetch)
    except FetchError as exc:
        message = f"could not read the repo from the Hub: {exc}"
        return Result(spec, "", [Finding(GAP, message, Severity.INFO, repo)])
    findings = []
    if revision != sha:
        message = (
            f"not pinned to a commit: {revision or 'main'} is {sha} today, and the code that "
            f'runs at load can change with it. Load with revision="{sha}"'
        )
        findings.append(Finding("BKT-HF-010", message, Severity.INFO, repo))
    budget = [0, 0]  # files and bytes read, across every repo
    more, files, entries, others = _read_repo(names, read, "", budget, repo)
    findings += more
    for other, modules in others.items():
        findings.append(_unpinned_other(other))
        try:
            other_sha, other_names, other_read = _hub_reader(other, "main", fetch)
        except FetchError as exc:
            message = f"could not read {other} from the Hub: {exc}"
            findings.append(Finding(GAP, message, Severity.INFO, other))
            continue
        prefix = f"{other}@{other_sha}/"
        gaps, more_files = _collect(other_read, list(modules), prefix, budget)
        findings += gaps
        files |= more_files
        entries |= {
            (prefix + module, cls) for module, classes in modules.items() for cls in classes
        }
    return Result(f"{repo}@{sha}", "", findings + _check_code(files, entries))


def _unpinned_other(other: str) -> Finding:
    message = (
        f"auto_map loads code from {other} at its main branch, whatever revision this "
        "repo is loaded at (transformers' code_revision), so it can change"
    )
    return Finding("BKT-HF-010", message, Severity.LOW, other)


# --- Reading a repo ----------------------------------------------------------------


def _safe(name: str) -> bool:
    """A plain path inside the repo: relative, no .., no backslash."""
    return (
        bool(name)
        and not name.startswith("/")
        and "\\" not in name
        and "\0" not in name
        and (".." not in name.split("/"))
    )


def _folder_reader(root: Path) -> tuple[set[str], Read]:
    """The folder's top-level file names, and a reader for any file in it.

    Links are followed only inside the folder, or for a Hub cache snapshot
    (models--org--name/snapshots/<commit>), inside the cache's folder for
    that repo, where they point into blobs/.
    """
    base = root.resolve()
    cache = base.parent.name == "snapshots" and base.parent.parent.name.startswith("models--")
    inside = base.parent.parent if cache else base
    names = {p.name for p in root.iterdir() if p.is_file()}
    if (root / CUSTOM_GENERATE).exists():
        names.add(CUSTOM_GENERATE)

    def read(name: str) -> bytes:
        path = root / name
        if not path.resolve().is_relative_to(inside):
            raise _Gap("a link out of the repo, not followed", "BKT-SKIP-004")
        if not path.is_file():
            raise _Gap("not in the repo")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise _Gap(f"over {MAX_FILE_BYTES} bytes, not read")
        return path.read_bytes()

    return names, read


def _hub_reader(repo: str, revision: str, fetch: Fetch) -> tuple[str, set[str], Read]:
    """The commit a revision names, its file names, and a reader for its files.

    Files are fetched by commit and checked against the blob id (or LFS sha256)
    the Hub lists for that commit before they are read.
    """
    quoted = urllib.parse.quote(revision, safe="")
    url = f"https://huggingface.co/api/models/{repo}/revision/{quoted}?blobs=true"
    try:
        info = json.loads(fetch(url, MAX_API_BYTES))
        sha = info["sha"]
        siblings = {s["rfilename"]: s for s in info["siblings"]}
    except (ValueError, KeyError, TypeError) as exc:
        raise FetchError(f"unexpected answer from the Hub API: {exc}") from exc
    if not isinstance(sha, str) or not _COMMIT.fullmatch(sha):
        raise FetchError("the Hub API gave no commit id")

    def read(name: str) -> bytes:
        entry = siblings.get(name)
        if not isinstance(entry, dict):
            raise _Gap("not in the repo at this commit")
        if not isinstance(entry.get("size"), int) or entry["size"] > MAX_FILE_BYTES:
            raise _Gap(f"over {MAX_FILE_BYTES} bytes, not fetched")
        try:
            data = fetch(
                f"https://huggingface.co/{repo}/resolve/{sha}/{urllib.parse.quote(name)}",
                MAX_FILE_BYTES,
            )
        except FetchError as exc:
            raise _Gap(f"could not fetch: {exc}") from exc
        lfs = entry.get("lfs")
        if isinstance(lfs, dict):
            matches = hashlib.sha256(data).hexdigest() == lfs.get("sha256")
        else:
            blob = hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False)
            matches = blob.hexdigest() == entry.get("blobId")
        if not matches:
            raise _Gap("does not match the file the Hub lists for this commit, not read")
        return data

    return sha, {n for n in siblings if isinstance(n, str)}, read


def _read_repo(
    names: set[str], read: Read, prefix: str, budget: list[int], own: str = ""
) -> tuple[list[Finding], dict[str, bytes], set[tuple[str, str]], dict[str, dict[str, set[str]]]]:
    """Read the configs at the repo's root and the code they name.

    Returns findings (gaps), the code files by path, the (file, class) pairs
    transformers builds, and code named in other repos: {repo: {file: classes}}.
    """
    findings: list[Finding] = []
    local: dict[str, set[str]] = {}
    others: dict[str, dict[str, set[str]]] = {}
    configs = sorted(
        n for n in names if "/" not in n and n.endswith(("config.json", "modules.json"))
    )
    for name in configs:
        if budget[0] >= MAX_FILES or budget[1] > MAX_TOTAL_BYTES:
            message = f"more than {MAX_FILES} files or {MAX_TOTAL_BYTES} bytes, not read"
            findings.append(Finding(GAP, message, Severity.INFO, prefix + name))
            break
        try:
            data = read(name)
            budget[0], budget[1] = budget[0] + 1, budget[1] + len(data)
            config = json.loads(data)
        except _Gap as gap:
            findings.append(Finding(gap.rule, str(gap), Severity.INFO, prefix + name))
            continue
        except (ValueError, RecursionError) as exc:
            message = f"could not parse as JSON: {exc}"
            findings.append(Finding("BKT-SKIP-003", message, Severity.INFO, prefix + name))
            continue
        for reference in _references(config, names):
            repo, sep, rest = (
                reference.rpartition("--") if "--" in reference else ("", "", reference)
            )
            module, _, cls = rest.partition(".")
            if reference.count("--") > 1 or rest.count(".") != 1:
                continue  # transformers cannot split it into module.Class, so loads nothing
            if not _safe(f"{module}.py") or (sep and (not _REPO.fullmatch(repo) or ".." in repo)):
                message = f"names {reference!r}, a file outside the repo or a bad repo id: not read"
                findings.append(Finding(GAP, message, Severity.INFO, prefix + name))
            else:
                # transformers loads its own repo's code at the revision asked for
                other = sep and repo.lower() != own.lower()
                target = others.setdefault(repo, {}) if other else local
                target.setdefault(f"{module}.py", set()).add(cls)
    if CUSTOM_GENERATE in names:
        local.setdefault(CUSTOM_GENERATE, set())
    gaps, files = _collect(read, list(local), prefix, budget)
    entries = {(prefix + module, cls) for module, classes in local.items() for cls in classes}
    return findings + gaps, files, entries, others


def _references(config: object, names: set[str]) -> Iterator[str]:
    """Class references in a config: auto_map values, custom_pipelines impls, and
    sentence-transformers modules.json types that name a .py file in the repo."""
    if isinstance(config, dict):
        todo = [config.get("auto_map")]
        pipelines = config.get("custom_pipelines")
        if isinstance(pipelines, dict):
            todo += [p.get("impl") for p in pipelines.values() if isinstance(p, dict)]
        while todo:
            value = todo.pop()
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                todo += value.values()
            elif isinstance(value, list):
                todo += value
    elif isinstance(config, list):  # modules.json
        for module in config:
            kind = module.get("type") if isinstance(module, dict) else None
            local = isinstance(kind, str) and f"{kind.partition('.')[0]}.py" in names
            if local or (isinstance(kind, str) and "--" in kind):
                yield kind


def _collect(read: Read, modules: list[str], prefix: str, budget: list[int]) -> tuple[list, dict]:
    """The named code files and every file they import relatively, as transformers
    fetches them. budget: [files, bytes] read so far, for the limits; updated."""
    findings, files = [], {}
    queue = list(dict.fromkeys(modules))
    for name in queue:
        if budget[0] >= MAX_FILES or budget[1] > MAX_TOTAL_BYTES:
            message = f"more than {MAX_FILES} files or {MAX_TOTAL_BYTES} bytes, not read"
            findings.append(Finding(GAP, message, Severity.INFO, prefix + name))
            break
        try:
            data = read(name)
        except _Gap as gap:
            findings.append(Finding(gap.rule, str(gap), Severity.INFO, prefix + name))
            continue
        files[prefix + name] = data
        budget[0], budget[1] = budget[0] + 1, budget[1] + len(data)
        for plain, dotted in _RELATIVE.findall(data.decode("utf-8", "replace")):
            module = plain or dotted
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), f"{module}.py"))
            if not _safe(target):
                message = f"imports .{module}, which is outside the repo: not read"
                findings.append(Finding(GAP, message, Severity.INFO, prefix + name))
            elif target not in queue:
                queue.append(target)
    return findings, files


# --- What runs at load -----------------------------------------------------------


class _Module:
    """One code file: its module-level functions and classes, and its imports."""

    def __init__(self, key: str, tree: ast.Module) -> None:
        self.key, self.tree = key, tree
        self.defs: dict[str, Function] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.imports: dict[str, tuple[str, str | None]] = {}  # name -> (file, name or module)
        self.aliases: dict[str, str] = {}  # absolute imports: local name -> dotted name
        for stmt in _module_level(tree.body):
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.defs[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                self.classes[stmt.name] = stmt
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                folder = posixpath.dirname(key)
                for _ in range(node.level - 1):
                    folder = posixpath.dirname(folder)
                for alias in node.names:
                    local = alias.asname or alias.name
                    if node.module:
                        path = posixpath.join(folder, node.module.replace(".", "/"))
                        self.imports[local] = (f"{path}.py", alias.name)
                    else:
                        self.imports[local] = (posixpath.join(folder, f"{alias.name}.py"), None)
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name


def _module_level(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Statements at module level, inside if, try and with blocks too, not in defs."""
    for stmt in body:
        yield stmt
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for field in ("body", "orelse", "finalbody"):
                yield from _module_level(getattr(stmt, field, []))
            for block in [*getattr(stmt, "handlers", []), *getattr(stmt, "cases", [])]:
                yield from _module_level(block.body)


def _import_time_calls(node: ast.AST) -> Iterator[ast.Call]:
    """Calls made when a module is imported: not in function bodies or a __main__ block."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        for decorator in node.decorator_list:  # @register applies register
            if not isinstance(decorator, ast.Call):
                yield ast.copy_location(ast.Call(decorator, [], []), decorator)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for part in [*node.decorator_list, node.args]:
            yield from _import_time_calls(part)
        return
    if isinstance(node, ast.Lambda):
        return
    if isinstance(node, ast.If) and _is_main_check(node.test):
        for part in node.orelse:
            yield from _import_time_calls(part)
        return
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _import_time_calls(child)


class _Follower:
    """Functions and methods that run at load, found by following references from
    the classes transformers builds and from each module's import-time code.

    A class transformers builds runs its dunder methods (but __call__) and any
    _HOOKS method, in it or a base class in the repo; its config_class is built
    too. Any other class of the repo that runs code reaches runs its dunders.
    Inside code that runs, a reference to a function or class of the repo (by
    name, relative import or self/cls/super()) reaches it. Methods the user
    calls (forward, generate, chat) are reached only this way.
    """

    def __init__(self, modules: dict[str, _Module]) -> None:
        self.modules = modules
        self.reached: dict[str, dict[Function, str]] = {key: {} for key in modules}
        self.classes: set[tuple[ast.ClassDef, bool]] = set()
        self.seen: set[tuple[Function, tuple]] = set()  # (function, classes self may be)
        self.fetching: dict[str, list[tuple[int, str]]] = {key: [] for key in modules}

    def resolve(self, key: str, name: str, depth: int = 0) -> tuple[str, ast.AST | None] | None:
        """What a name in a file is: (file, function or class), (file, None) for a
        module, or None when it is not the repo's."""
        module = self.modules.get(key)
        if module is None or depth > 20:
            return None
        if name in module.defs:
            return key, module.defs[name]
        if name in module.classes:
            return key, module.classes[name]
        if name in module.imports:
            target, attribute = module.imports[name]
            if target in self.modules:
                return (
                    (target, None)
                    if attribute is None
                    else self.resolve(target, attribute, depth + 1)
                )
        return None

    def resolve_expr(self, key: str, node: ast.AST) -> tuple[str, ast.AST | None] | None:
        if isinstance(node, ast.Name):
            return self.resolve(key, node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner = self.resolve(key, node.value.id)
            if owner and owner[1] is None:
                return self.resolve(owner[0], node.attr)
        return None

    def lineage(self, key: str, cls: ast.ClassDef, seen: frozenset = frozenset()) -> list:
        """The class and its base classes defined in the repo, nearest first."""
        found = [(key, cls)]
        for base in cls.bases:
            target = self.resolve_expr(key, base)
            if target and isinstance(target[1], ast.ClassDef) and target[1] not in seen:
                found += self.lineage(target[0], target[1], seen | {cls})
        return found

    def reach_class(self, key: str, cls: ast.ClassDef, built: bool) -> None:
        if (cls, built) in self.classes:
            return
        self.classes.add((cls, built))
        lineage = self.lineage(key, cls)
        for owner_key, owner in lineage:
            for item in owner.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    dunder = item.name.startswith("__") and item.name.endswith("__")
                    if (dunder and item.name != "__call__") or (built and item.name in _HOOKS):
                        self.reach(owner_key, item, f"{owner.name}.{item.name}", lineage)
                elif built and isinstance(item, (ast.Assign, ast.AnnAssign)) and item.value:
                    targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                    if any(isinstance(t, ast.Name) and t.id == "config_class" for t in targets):
                        self.reach_target(owner_key, self.resolve_expr(owner_key, item.value), True)

    def reach_target(self, key: str, target: tuple | None, built: bool = False) -> None:
        if target and isinstance(target[1], ast.ClassDef):
            self.reach_class(target[0], target[1], built)
        elif target and isinstance(target[1], (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.reach(target[0], target[1], target[1].name, [])

    def reach(self, key: str, function: Function, label: str, lineage: list) -> None:
        if (function, tuple(c for _, c in lineage)) in self.seen:
            return
        self.seen.add((function, tuple(c for _, c in lineage)))
        self.reached[key].setdefault(function, label)
        for node in ast.walk(function):
            if isinstance(node, ast.Call):
                self.check_call(key, node)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self.reach_target(key, self.resolve(key, node.id))
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                owner = node.value
                own = (isinstance(owner, ast.Name) and owner.id in ("self", "cls")) or (
                    isinstance(owner, ast.Call) and _dotted(owner.func) == "super"
                )
                if own:
                    methods = lineage
                else:
                    target = self.resolve_expr(key, owner)
                    if target and target[1] is None:  # module.function
                        self.reach_target(key, self.resolve(target[0], node.attr))
                    is_class = target and isinstance(target[1], ast.ClassDef)
                    methods = self.lineage(target[0], target[1]) if is_class else []
                for owner_key, cls in methods:
                    for item in cls.body:
                        is_method = isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        if is_method and item.name == node.attr:
                            self.reach(owner_key, item, f"{cls.name}.{item.name}", methods)

    def check_call(self, key: str, call: ast.Call) -> None:
        """Calls that fetch more code: hub downloads of .py files, dynamic module
        loaders, another repo's remote code. Kept as (line, detail) per file."""
        name = _dotted(call.func, self.modules[key].aliases)
        last = name.rpartition(".")[2] or (
            call.func.attr if isinstance(call.func, ast.Attribute) else ""
        )
        trusted = any(
            k.arg == "trust_remote_code"
            and isinstance(k.value, ast.Constant)
            and k.value.value is True
            for k in call.keywords
        )
        python = any(
            isinstance(c, ast.Constant) and isinstance(c.value, str) and c.value.endswith(".py")
            for c in ast.walk(call)
        )
        if trusted:
            detail = "loads another repo's remote code (trust_remote_code=True)"
        elif last in _RUNS_FETCHED or name == "torch.hub.load":
            detail = f"loads code from elsewhere with {last}"
        elif last in _HUB_DOWNLOADS:
            detail = f"fetches a .py file with {last}" if python else f"download:{last}"
        elif name in _FILE_LOADERS or last == "exec_module":
            detail = f"run:{name or last}"
        else:
            return
        self.fetching[key].append((call.lineno, detail))


def _dotted(node: ast.AST, aliases: dict[str, str] | None = None) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, aliases)
        return f"{base}.{node.attr}" if base else ""
    if isinstance(node, ast.Name):
        return (aliases or {}).get(node.id, node.id)
    return ""


def _check_code(files: dict[str, bytes], entries: set[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    modules: dict[str, _Module] = {}
    for key, data in files.items():
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                modules[key] = _Module(key, ast.parse(data))
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            message = f"could not parse as Python: {exc}"
            findings.append(Finding("BKT-SKIP-003", message, Severity.INFO, key))
    follower = _Follower(modules)
    try:
        with _deep_recursion():
            findings += _follow(follower, modules, entries)
    except RecursionError:
        message = "calls nest too deeply to follow them all"
        findings += [Finding("BKT-SKIP-003", message, Severity.INFO, key) for key in modules]
    for key in modules:
        findings += _file_findings(key, files[key], follower.reached[key], follower.fetching[key])
    return findings


def _follow(
    follower: _Follower, modules: dict[str, _Module], entries: set[tuple[str, str]]
) -> list[Finding]:
    """Reach what runs at load: the built classes, and each module's import-time code."""
    findings = []
    for key, cls in sorted(entries):
        target = follower.resolve(key, cls)
        if target and isinstance(target[1], ast.ClassDef):
            follower.reach_class(target[0], target[1], built=True)
        elif key in modules and cls in _bound_names(modules[key].tree):
            message = f"auto_map names {cls}, which is not a class defined in the repo: not read"
            findings.append(Finding(GAP, message, Severity.INFO, key))
    for key, module in modules.items():
        for call in _import_time_calls(module.tree):
            follower.check_call(key, call)
            follower.reach_target(key, follower.resolve_expr(key, call.func))
        for cls in module.classes.values():  # defining a class runs these
            for keyword in cls.keywords:
                if keyword.arg == "metaclass":
                    follower.reach_target(key, follower.resolve_expr(key, keyword.value))
            lineage = follower.lineage(key, cls)
            for owner_key, owner in lineage[1:]:
                for item in owner.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "__init_subclass__":
                        follower.reach(owner_key, item, f"{owner.name}.{item.name}", lineage)
    return findings


def _bound_names(tree: ast.Module) -> set[str]:
    """Names module-level code binds: a class bound some other way may run code we
    did not read. A name it never binds cannot be loaded at all."""
    names = set()
    for stmt in _module_level(tree.body):
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            names |= {(a.asname or a.name).split(".")[0] for a in stmt.names}
        for node in ast.walk(stmt) if not isinstance(stmt, ast.ClassDef) else ():
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
    return names


def _file_findings(
    key: str, data: bytes, reached: dict[Function, str], fetching: list[tuple[int, str]]
) -> list[Finding]:
    """One finding per kind of hit, as for package code, for what runs at load: the
    module's import-time code and the functions reached. Hidden code and
    exfiltration channels count anywhere."""
    try:
        top, everything = analyse(data, True), analyse(data, False)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return [Finding("BKT-SKIP-003", f"could not parse as Python: {exc}", Severity.INFO, key)]
    spans = sorted((f.lineno, f.end_lineno or f.lineno, label) for f, label in reached.items())
    hits: dict[tuple[str, int], Hit] = {}
    for hit in top:
        hits.setdefault((hit.kind, hit.line), hit)
    for hit in everything:
        inside = [label for start, end, label in spans if start <= hit.line <= end]
        if hit.kind in _ANYWHERE:
            hits.setdefault((hit.kind, hit.line), hit)
        elif inside:
            detail = f"{hit.detail} (in {inside[-1]}(), run at model load)"
            hits.setdefault((hit.kind, hit.line), Hit(hit.kind, hit.line, detail))
    by_kind: dict[str, list[Hit]] = {}
    for hit in hits.values():
        if hit.kind == "exec_file":
            hit = Hit("exec", hit.line, f"execs {hit.detail}")
        by_kind.setdefault(hit.kind, []).append(hit)
    findings = []
    for kind, kind_hits in by_kind.items():
        rule, severity = _CODE_RULES[kind]
        details = "; ".join(sorted({h.detail for h in kind_hits}))
        message = f"runs at model load: {details}" if "{when}" in rule else details
        lines = sorted({h.line for h in kind_hits})
        findings.append(Finding(rule.format(when="HF"), message, severity, key, {"lines": lines}))
    if "network" in by_kind and ("secrets" in by_kind or "environ" in by_kind):
        message = "reads credentials or the whole environment and uses the network at model load"
        findings.append(Finding("BKT-HF-008", message, Severity.CRITICAL, key))
    # More code fetched at load: a call that does it, or a download and a run in one file.
    more = [(line, d) for line, d in fetching if not d.startswith(("download:", "run:"))]
    downloads = "network" in by_kind or any(d.startswith("download:") for _, d in fetching)
    runs = by_kind.keys() & {"exec", "hidden"} or any(d.startswith("run:") for _, d in fetching)
    if downloads and runs:
        lines = [h.line for k in ("network", "exec", "hidden") for h in by_kind.get(k, [])]
        lines += [line for line, d in fetching if d.startswith(("download:", "run:"))]
        more += [(line, "downloads and runs code") for line in lines]
    if more:
        details = "; ".join(sorted({d for _, d in more}))
        lines = sorted({line for line, _ in more})
        message = f"fetches more code at model load: {details}"
        findings.append(Finding("BKT-HF-009", message, Severity.MEDIUM, key, {"lines": lines}))
    return findings


# --- Network ---------------------------------------------------------------------


def allowed_url(url: str) -> bool:
    """https on huggingface.co, or a huggingface.co or hf.co host (the Hub's CDNs)."""
    parts = urllib.parse.urlparse(url)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and port in (None, 443)
        and not parts.username
        and not parts.password
        and (host in ("huggingface.co", "hf.co") or host.endswith((".huggingface.co", ".hf.co")))
    )


class _HubOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not allowed_url(newurl):
            raise FetchError(f"redirect to {newurl} refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url: str, max_bytes: int) -> bytes:
    """GET an https URL on the Hub, up to max_bytes. FetchError for anything else."""
    if not allowed_url(url):
        raise FetchError(f"{url} is not on the Hugging Face Hub")
    opener = urllib.request.build_opener(_HubOnlyRedirects)
    # S310: https and the host were checked above, and redirects are checked too.
    request = urllib.request.Request(url, headers={"User-Agent": "buckthorn"})  # noqa: S310
    try:
        with opener.open(request, timeout=60) as response:  # noqa: S310
            data = response.read(max_bytes + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise FetchError(str(exc)) from exc
    if len(data) > max_bytes:
        raise FetchError(f"larger than {max_bytes} bytes")
    return data
