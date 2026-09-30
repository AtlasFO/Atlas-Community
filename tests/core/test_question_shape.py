"""A question asks for a shape of answer (a number, named items, a person,
a time) and an answer that lacks it is told so, in both report languages."""
from core import answer_synthesis as syn
from core import investigation_tasks as tasks
from core.report_i18n import t


def test_question_kinds_in_both_languages():
    cases = [
        ("How many images were recovered?", "en", "count"),
        ("Wie viele Bilder wurden gefunden?", "de", "count"),
        ("Which files were deleted from the volume?", "en", "enumeration"),
        ("Welche Dateien wurden gelöscht?", "de", "enumeration"),
        ("What images did the user download?", "en", "enumeration"),
        ("Who used the account after hours?", "en", "who"),
        ("Wer hat das Konto verwendet?", "de", "who"),
        ("When was the file copied?", "en", "when"),
        ("Wann wurde die Datei kopiert?", "de", "when"),
        ("Was the USB stick used on the host?", "en", "yes_no"),
        ("Wurde der USB-Stick am Host verwendet?", "de", "yes_no"),
        ("Was geschah auf dem Host?", "de", "what"),
        ("What happened on the host?", "en", "what"),
    ]
    for question, language, kind in cases:
        assert syn.question_kind(question, language) == kind, question


def test_a_count_needs_a_number_and_nameable_items_need_a_name():
    count = "How many images were recovered from the drive?"
    assert syn.answer_shape_gap(count, ["Several images were recovered from the drive."]) == "count"
    assert syn.answer_shape_gap(count, ["Four images were recovered from the drive."]) == ""
    assert syn.answer_shape_gap("Wie viele Bilder?", ["Es wurden keine Bilder gefunden."], "de") == ""
    which = "Which files did the user upload?"
    assert syn.answer_shape_gap(which, ["The user uploaded images over FTP."]) == "named"
    assert syn.answer_shape_gap(which, ["The user uploaded rhino1.jpg and rhino3.jpg over FTP."]) == ""
    assert syn.answer_shape_gap(which, ["The uploads were: a diary, a photo, a note."]) == ""
    assert syn.answer_shape_gap("Which accounts were used?", ["The jane account was used."]) == ""
    assert syn.answer_shape_gap(count, []) == ""


def test_the_report_answer_carries_the_gap():
    graph = {"nodes": {"C1": {"id": "C1", "kind": "conclusion", "status": "new",
                              "confidence": "LIKELY",
                              "statement": "Several images were recovered from the USB drive."}}}
    task = {"text": "How many images were recovered?", "status": "answered",
            "related_claim_ids": ["C1"]}
    ans = syn.answer_for_task(task, graph)
    assert ans["has_answer"] and ans["shape_gap"] == "count"
    assert t("shape_count", "de").startswith("Die Frage verlangt eine Zahl")


def test_closing_a_task_without_the_shape_is_told_so(tmp_path, monkeypatch):
    graph = {"nodes": {"C1": {"id": "C1", "kind": "claim", "status": "new",
                              "statement": "Images were uploaded over FTP."}}}
    monkeypatch.setattr("core.claim_graph.load_graph", lambda case_dir: graph)
    task = {"text": "Which files were uploaded?", "status": "answered",
            "related_claim_ids": ["C1"]}
    assert "name none" in tasks._answer_shape_hint(str(tmp_path), task)
    task["text"] = "Was anything uploaded?"
    assert tasks._answer_shape_hint(str(tmp_path), task) is None
