"""Shared fixture: a temporary brain tree seeded from the real templates."""

import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

NOTE = """---
title: "{title}"
type: "{type}"
created: "{created}"
updated: "{updated}"
status: "active"
source_classification: "{classification}"
confidence: "medium"
tags: [{tags}]
related: [{related}]
source: {{type: "manual", url: "", description: ""}}
origin: {{case_id: "{origin_case}", run_id: "{run_id}", command: "{command}"}}
entities: {{cases: [{cases}], tools: [{tools}], techniques: [], actors: [], cves: []}}
---

# {title}

{body}
"""


def make_note(root: Path, rel: str, title: str, type: str = "note",
              tags: str = "", related: str = "", body: str = "content",
              classification: str = "internal", cases: str = "",
              tools: str = "", created: str = "2026-07-01",
              updated: str = "2026-07-01", run_id: str = "",
              origin_case: str = "", command: str = "") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(NOTE.format(title=title, type=type, tags=tags,
                                related=related, body=body,
                                classification=classification,
                                cases=cases, tools=tools,
                                created=created, updated=updated,
                                run_id=run_id, origin_case=origin_case,
                                command=command),
                    encoding="utf-8")
    return path


ENV_NOTE = """---
title: "{title}"
type: "environment"
client: "{client}"
created: "2026-07-01"
updated: "2026-07-01"
last_verified: "{last_verified}"
status: "active"
source_classification: "internal"
confidence: "medium"
tags: [{tags}]
related: []
source: {{type: "{source_type}", url: "", description: ""}}
entities: {{cases: [], tools: [], techniques: [], actors: [], cves: []}}
---

# {title}

{body}
"""


def make_env_note(root, client: str, title: str, body: str = "baseline fact",
                  source_type: str = "client_provided",
                  last_verified: str = "2026-07-01", tags: str = "",
                  rel: str = "") -> Path:
    path = root / (rel or f"wiki/environments/{client}/"
                          f"{title.lower().replace(' ', '-')}.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ENV_NOTE.format(title=title, client=client, body=body,
                                    source_type=source_type,
                                    last_verified=last_verified, tags=tags),
                    encoding="utf-8")
    return path


@pytest.fixture
def brain(tmp_path, monkeypatch):
    root = tmp_path / "brain"
    for d in ("memory", "wiki/cases", "wiki/tools", "wiki/techniques",
              "wiki/actors", "wiki/concepts", "wiki/environments",
              "logs/decisions", "logs/research",
              "logs/runs", "inbox/raw", "inbox/processed",
              "inbox/memory-candidates", "indexes",
              "analytics/snapshots", "analytics/reports", "analytics/globe"):
        (root / d).mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "brain" / "templates", root / "templates")
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(root))
    return root
