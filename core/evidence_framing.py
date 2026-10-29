"""The framing sentences that tell the model what the case's exports and
images are for (ATLAS_EVIDENCE_FRAMING): one owner for every sentence the
evidence inventory, the evidence profile and the run-budget messages print.

Exports are an index of what the images hold, never their replacement: a
row names the source file inside an image it was parsed from and carries
only what its parser kept. The handle clause (how one file inside an image
is read) is core.contents_index's, so the sentence and the tool contract
cannot drift; ATLAS_IMAGE_HANDLES toggles only that clause.
"""
from __future__ import annotations

import os
from typing import Optional

from core.envfile import env_flag


def framing_on() -> bool:
    return env_flag("ATLAS_EVIDENCE_FRAMING", True)


def framing_lines(case_dir: Optional[str | os.PathLike] = None, *, handles: Optional[bool] = None) -> dict[str, str]:
    """Every framing sentence by its place. ``handles`` None reads the
    handle switch at call time."""
    from core.contents_index import HANDLE_CLAUSE, HANDLE_CLAUSE_OFF, image_handles_on
    clause = HANDLE_CLAUSE if (image_handles_on() if handles is None else handles) else HANDLE_CLAUSE_OFF
    return {
        "brief": ("The brief (CASE.md, in your system prompt) describes this evidence set; where it and "
                  "these defaults differ, the brief wins."),
        "policy_tail": ("Exports under already_processed are an index of what the images hold: a row names "
                        "the source file inside an image it was parsed from, and carries only what its parser "
                        "kept. The images are the authority. Event logs, hives, Prefetch, the MFT, browser and "
                        "mail stores, transcripts and server logs inside the images are reachable: "
                        f"{clause}. Do not claim evidence is missing when it is listed here, in an export's "
                        "rows or in the index."),
        "relevance": ("Search exports to find where to look; read the source inside the image when the "
                      "question needs what the export left out."),
        "already_processed": ("An index of what the images hold: query these to find rows and the source "
                              "file each row came from, then read that source for anything the export does "
                              "not carry."),
        "eventlog_reason": ("Parsed event-log exports present: search them to find where to look; they carry "
                            "only the channels and event ids their parser kept, so read the log itself for "
                            "anything else."),
        "first_action": ("When an artifact family is relevant, start from the exports to find where to look, "
                         "then read the source inside the image."),
        "needs_processing": ("Address needs_processing when a question reaches those classes; an export does "
                             "not cover what it did not parse."),
        "rule": ("Forensic tools unlock after this assessment. Catalog = reference map to draw from. "
                 "Relevance/time-window scopes depth. Exports point where to look; the images are the "
                 "authority. Skip only absent media."),
        "profile_rule": ("- Search exports with table.* to find where to look; read the source inside the "
                         f"image for what the export left out ({clause})."),
        "turn_advisory": ("Exports are an index; the images are the authority: a question an export cannot "
                          "settle is settled by reading the source inside the image. Avoid memory tools when "
                          "no memory image exists."),
        "stall_switch": ("read an unread source inside an image, or search an export to find where to look"),
    }
