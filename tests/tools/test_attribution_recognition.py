"""The attribution recognisers read an account with a dot and a sentence
that runs on past a file name. Invented fixtures only (jane.doe, Alice)."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates._match import named_things_in_text
from tools._gates.named_actor_attribution_grounding import actor_names
from tools._gates.principal_attribution_grounding import binds_account_to_person


def _ctx(desc):
    return SimpleNamespace(description=desc, supporting_evidence="", idx=SimpleNamespace(by_call_id={}),
                           input_call_ids=[], linked_call_id=0, log=MagicMock(), window=[])


def test_an_account_with_a_dot_bound_to_the_person_its_name_spells():
    assert binds_account_to_person(_ctx("The account jane.doe was used by Jane during the session"))


def test_prose_before_a_file_name_is_not_part_of_it():
    assert "alice" not in named_things_in_text("Alice copied report.docx to the share and then logged off")
    assert "report" in named_things_in_text("Alice copied report.docx to the share")
    assert "q3 plan" in named_things_in_text("the file 'Q3 plan.docx' was opened")
    assert actor_names(_ctx("Alice copied report.docx to the share and then logged off")) == {"Alice"}


def test_a_records_label_names_its_source_not_an_actor():
    """A capitalised run written as a log record's label (in parentheses after
    the log, before its event id) is read whole: its last words are no
    person. Public provider names, invented host and account."""
    label = ("CORP-SRV01's System log (Service Control Manager 7045) lists a new service; the archive was "
             "staged by it at 09:12.")
    assert actor_names(_ctx(label)) == set()
    assert actor_names(_ctx("The Application log (Windows Error Reporting 1001) shows the archive staged.")) == set()
    assert "Doe" in actor_names(_ctx("Jane Doe staged the archive on CORP-SRV01."))
    assert "Doe" in actor_names(_ctx("The account jdoe (Jane Doe) staged the archive."))


def test_a_person_before_a_date_or_a_number_in_prose_stays_a_candidate():
    assert {"Jane", "Doe"} & actor_names(_ctx("Jane Doe 2031-03-04 staged the archive on CORP-SRV01."))
    assert "Doe" in actor_names(_ctx("Account Jane Doe 4720 staged the archive."))
    assert actor_names(_ctx("The Application log (Windows Error Reporting 1001) shows the archive staged.")) == set()
