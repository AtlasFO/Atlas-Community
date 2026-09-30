"""Instruction-like text inside evidence content.

A forensic tool returns what the evidence holds, and the evidence can hold
text written for an automated reader rather than a person: a line that
addresses the analyst, tells it to disregard its rules or findings, or
dictates a verdict. Such text is data with a meaning of its own (an
attempt to steer the analysis) and never a directive. This module finds
it, so the trace can stamp the output that carries it, the model can see
it named in the result it reads, and a finding that leans on such output
can be checked (tools/_gates/instruction_text_grounding.py).

Detection is deliberately narrow. Each pattern needs the text to address
an analyst or assistant, to speak of overriding instructions, rules or
findings, or to dictate a verdict to its reader. Ordinary log lines,
configuration files and event XML must not match: a match adds a label
and an advisory note, and a label that appeared on routine output would
teach the reader to ignore it.
"""
from __future__ import annotations

import re

# Who a planted message would address.
_READER = r"(?:ai|a\.i\.|assistant|analyst|llm|language model|chatbot|atlas)"
# What it would ask the reader to drop.
_RULES = (r"(?:instructions?|prompts?|rules?|directives?|guidelines?|"
          r"findings?|context|orders?|constraints?|conclusions?)")

_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        # "ignore all previous instructions", "disregard your prior findings"
        rf"\b(?:ignore|disregard|forget|override|overrule|discard)\b"
        rf"[^.\n]{{0,40}}?\b(?:all|your|previous|prior|above|earlier|"
        rf"preceding|existing|original|these|those)\b[^.\n]{{0,40}}?\b{_RULES}\b",
        # "note to the AI analyst", "instructions for the assistant"
        rf"\b(?:note|message|memo|instructions?|prompt|directive|attention|"
        rf"reminder)s?\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?{_READER}\b",
        # "you are an AI", "if you are a language model", "as an AI"
        rf"\b(?:you are|you're|if you are)\s+(?:an?\s+|the\s+)?{_READER}\b"
        rf"|\bas an? (?:ai|language model|llm|chatbot)\b",
        # the vocabulary of a model's own instructions, which no evidence
        # has a reason to carry
        r"\b(?:system|developer)\s+prompt\b|\bdeveloper\s+(?:message|instruction)s?\b",
        # chat-template control tokens
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[/?INST\]|<<SYS>>",
        # a verdict dictated to the reader: "please record no findings"
        r"\b(?:please|just|you (?:must|should|shall|will|need to))\s+"
        r"(?:record|report|write|state|conclude|say|respond|answer|output|"
        r"mark|declare)\b[^.\n]{0,50}?\b(?:no|zero|without)\s+"
        r"(?:findings?|incidents?|malicious|compromise|threats?|indicators?|evidence of)\b",
        # "the host is clean, do not ..." in the same breath
        r"\b(?:host|system|machine|device|server|workstation|endpoint)\s+is\s+"
        r"(?:clean|benign|not compromised|safe)\b[^.\n]{0,60}?"
        r"\b(?:do not|don't|no need|ignore|record no|report no)\b",
    )
)

_SNIPPET_CHARS = 160
_MAX_SNIPPETS = 5


def find_instruction_like(text: str, limit: int = _MAX_SNIPPETS) -> list[str]:
    """The distinct instruction-like passages in ``text``, each cut to a
    short snippet, at most ``limit`` of them. Empty when there are none."""
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for rx in _PATTERNS:
        for m in rx.finditer(text):
            snippet = " ".join(m.group(0).split())[:_SNIPPET_CHARS]
            key = snippet.casefold()
            if key in seen:
                continue
            seen.add(key)
            out.append(snippet)
            if len(out) >= limit:
                return out
    return out
