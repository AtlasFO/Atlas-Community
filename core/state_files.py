"""File names of the run's own state that Atlas writes under ``analysis/``
beside the trace, defined once so a writer and the readers that must
recognise them (core.provenance's output snapshot) agree. The trace, the
transcript (core.run_state) and the evidence index (core.evidence_index)
keep their names with their owners."""
from __future__ import annotations

# The Brain's record of the lessons injected into the prompt (agent.prompts).
BRAIN_INJECTION_MANIFEST = "brain_injection.json"
# The topics the Brain's auto-consult already answered (core.brain.auto_consult).
BRAIN_AUTO_TOPICS = "brain_auto_topics.json"
# The lessons the analyst consulted (tools.brain_tools).
BRAIN_CONSULTED = "brain_consulted.json"
# The EVTX parser's memo of the logs it parsed (tools.eztools).
EVTX_PARSE_MEMO = ".evtx_parse_registry.json"

STATE_FILE_NAMES = frozenset({BRAIN_INJECTION_MANIFEST, BRAIN_AUTO_TOPICS, BRAIN_CONSULTED, EVTX_PARSE_MEMO})
