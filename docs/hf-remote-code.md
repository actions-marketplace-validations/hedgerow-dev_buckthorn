# Hugging Face remote code and Hayward

Hayward reads model files. When a config has `auto_map` or ships
`trust_remote_code`, it raises `MFV-HF-002` (HIGH) and its verdict is
`remote_code`: the model runs the repo's own Python, and Hayward does not say
what that Python does. Its load guard refuses that code unless the repo is
named. Buckthorn can now read that code (see "Hugging Face remote code" in
[rules.md](rules.md)). These are options for joining the two. None is built.

## 1. Hayward calls Buckthorn when it sees auto_map

`hayward scan` finds `MFV-HF-002`, runs `buckthorn scan <model folder>
--format json` as a subprocess when it is installed, and shows Buckthorn's
verdict beside its own. Hayward keeps its one dependency, and the two tools
stay separate releases. A `remote_code` verdict becomes `remote_code (clean)`,
`remote_code (flagged)` or `remote_code (not_verified)`.

Open question: whether a clean Buckthorn verdict should lower `MFV-HF-002`, or
only add context. My view is context only at first, since Buckthorn does not
read what `forward` does.

## 2. The load guard asks for a pinned, checked commit

`hayward.guard.install(remote_code=["org/name"])` allows a repo at any
revision. A stricter mode could allow remote code only when `from_pretrained`
passes a commit id as `revision=` and `buckthorn.hf.scan_repo("org/name@<commit>")`
is clean for it. That needs the network at load and an import of `buckthorn`,
so it would be an opt-in extra (`hayward[remote-code]`).

## 3. One published verdict per repo and commit

`hayward verify` already reads published verdicts and fails on `remote_code`.
The verify service could also run `buckthorn hf org/name@<commit>` and publish
that verdict with the model's, so a repo whose remote code was read and found
clean at that commit is vouched for, and `--allow-gaps` is no longer the only
way through.

## 4. A shared receipt

Both tools write in-toto statements of the same shape. A combined receipt for a
repo at a commit would list the weight files by sha256 (Hayward) and the code
files by blob id (Buckthorn), so one attestation covers everything that loads.

Whatever the shape, the commit is key: transformers fetches code at load, so a
verdict without a commit id says nothing about the next load.
