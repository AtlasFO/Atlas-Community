"""The Brain Earth page's strings resolve in every dashboard language.

AtlasI18n.t() falls back to English and then to the key itself, so a key
missing from one table, or a placeholder spelled differently in one
language, raises no error anywhere: the page just shows English or a raw
key. These checks pin the page's keys against the tables in i18n.js.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "dashboard" / "brain_globe.html"
I18N = ROOT / "dashboard" / "assets" / "i18n.js"

# Evaluates i18n.js with the two browser globals it touches and prints its
# string tables, so a syntax error in the module fails here as well.
_DUMP = """
const fs = require("fs"), vm = require("vm");
const ctx = { localStorage: { getItem: () => null, setItem() {} },
              document: { documentElement: { dataset: {} } } };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8") +
                "\\n;globalThis.STRINGS = AtlasI18n.STRINGS;", ctx);
process.stdout.write(JSON.stringify(ctx.STRINGS));
"""

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node not installed")


@pytest.fixture(scope="module")
def tables():
    done = subprocess.run(["node", "-e", _DUMP, str(I18N)],
                          capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def _page_keys(html):
    keys = set(re.findall(r'\btr\("(globe\.\w+)"', html))
    keys |= set(re.findall(r'data-i18n="(globe\.\w+)"', html))
    for base in re.findall(r'\btrCount\("(globe\.\w+)"', html):
        keys |= {base + "One", base + "Many"}   # the page's plural helper
    return keys


def _placeholders(text):
    return sorted(re.findall(r"\{(\w+)\}", text))


def test_every_key_the_page_uses_exists_in_every_language(tables):
    keys = _page_keys(PAGE.read_text(encoding="utf-8"))
    assert keys, "no globe.* keys found in brain_globe.html"
    for lang, table in tables.items():
        missing = sorted(k for k in keys if k not in table)
        assert not missing, f"{lang} lacks {missing}"


def test_globe_keys_and_placeholders_match_across_languages(tables):
    en = {k: v for k, v in tables["en"].items() if k.startswith("globe.")}
    for lang, table in tables.items():
        other = {k: v for k, v in table.items() if k.startswith("globe.")}
        assert sorted(other) == sorted(en), lang
        for key, text in en.items():
            assert _placeholders(other[key]) == _placeholders(text), (lang, key)


def test_static_fallback_text_is_the_english_string(tables):
    html = PAGE.read_text(encoding="utf-8")
    labels = re.findall(r'data-i18n="(globe\.\w+)"[^>]*>([^<]*)<', html)
    assert labels
    for key, text in labels:
        assert text == tables["en"][key], key


_T = """
const fs = require("fs"), vm = require("vm");
const ctx = { localStorage: { getItem: () => null, setItem() {} },
              document: { documentElement: { dataset: {} } } };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8") +
                "\\n;globalThis.OUT = AtlasI18n.t('x {v} y', {v: 'a$&b$$c'});", ctx);
process.stdout.write(ctx.OUT);
"""


def test_a_value_is_inserted_as_written():
    """Values are data (an error text, a date): a `$&` or `$$` in one is not a
    replacement pattern."""
    done = subprocess.run(["node", "-e", _T, str(I18N)],
                          capture_output=True, text=True, check=True)
    assert done.stdout == "x a$&b$$c y"
