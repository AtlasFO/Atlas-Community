"""What the community edition leaves out.

The community mirror is this tree minus the development-only paths that
.github/workflows/sync-community.yml excludes: devtools/ and its tests,
bin/atlas-dev, tests/live/, the regression harness (tests/regression/,
tests/replay/), benchmarks/, the demo runs kept for development, and the
brain's notes. A test that needs one of them skips there instead of
breaking collection, which would stop install.sh's post-install check before
a single test ran. The skip is keyed on the directory, not on an import or a
file failing, so a broken devtools import or a lost benchmark file in the full
tree still fails.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEVTOOLS_SHIPPED = (ROOT / "devtools").is_dir()
NO_DEVTOOLS = "devtools/ is not shipped in the community edition"
# devtools/ marks the full tree: the development data leaves with it.
NO_DEV_DATA = ("the benchmark answer keys and development runs are not "
               "shipped in the community edition")


def require_devtools() -> None:
    """Skip the calling test module when devtools/ is absent."""
    if not DEVTOOLS_SHIPPED:
        pytest.skip(NO_DEVTOOLS, allow_module_level=True)
