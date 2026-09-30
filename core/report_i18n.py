"""Report heading / label glossary (en / de).

Raw evidence lines, IOCs, paths, and usernames are never translated —
only structural labels and section titles.
"""
from __future__ import annotations

from typing import Any

GLOSSARY: dict[str, dict[str, str]] = {
    "en": {
        "report_title": "Forensic Investigation Report",
        "toc": "Table of Contents",
        "exec_summary": "1. Executive Summary",
        "scope_evidence": "2. Scope and Evidence",
        "key_findings": "3. Key Findings",
        "detailed_findings": "4. Detailed Findings",
        "timeline": "5. Attack Timeline",
        "gaps": "6. Evidence Gaps and Open Questions",
        "recommendations": "7. Recommendations",
        'indicators': 'Indicators',
        'ind_frame_incident': 'Frame: incident on the owner\'s systems. Attacker rows are block and hunt items; the owner\'s own assets are listed under Scope, never as block items. Verify ownership before deploying a block item.',
        'ind_frame_subject': 'Frame: examination of the device of the person under investigation. There is no attacker side to block; the rows are the case\'s key identifiers, and provider-held resources carry a preservation request.',
        'ind_counts': '{total} typed indicator(s) ({uses}); {affected} own asset(s) named in the findings; {review} prose-derived candidate(s) to review before use.',
        'ind_none': 'No typed indicator was recorded; {review} prose-derived candidate(s) await review before use.',
        'ind_see': 'The list with provenance is in `{md}`; the same rows for import are in `{csv}`.',
        'ind_files_missing': 'The indicator files could not be written for this report.',
        'use_block': 'block', 'use_contain': 'contain', 'use_hunt': 'hunt', 'use_request': 'request',
        'use_identify': 'identify', 'use_scope': 'scope', 'use_review': 'review',
        'response_do_now': 'Do now',
        'response_none': 'No recommendations were recorded for this scope.',
        'response_see_estate': 'Estate-wide measures are in the estate report.',
        'response_prior_note': "Items marked 'from prior knowledge' rest on what the analyst told Atlas before any evidence was read, not on findings.",
        'response_examination_note': "This case is an examination after the fact. The owner's duties remain: each measure below applies to systems still in service, and only if the owner has not already taken it. A measure derived from the ATT&CK mitigation table is a lesson for the owner, not a first-hour step.",
        'response_suspect_note': "The device or image belongs to the person under investigation: no remediation is recommended to its owner. Where a measure is warranted, it is an investigative next step, a preservation or legal-process request, notification of an identified third party, or an escalation of ongoing harm.",
        'response_owner_assumption': "The brief does not say whose system this is; the recommendations assume the owner is the victim.",
        'response_state_done': 'done',
        'response_phase_contain': 'Contain',
        'response_phase_eradicate': 'Eradicate',
        'response_phase_recover': 'Recover',
        'response_phase_harden': 'Harden',
        'response_phase_escalate': 'Escalate',
        'response_basis_lost': 'Rests on withdrawn findings — review before acting',
        'response_phase_investigate': 'Next investigative steps',
        'response_urgency_now': 'now',
        'response_urgency_soon': 'soon',
        'response_urgency_later': 'later',
        'response_scope_host': 'host',
        'response_scope_network': 'network',
        'response_scope_estate': 'estate',
        'response_source_prior_knowledge': 'from prior knowledge',
        'response_source_derived': 'derived from the findings',
        'response_source_recorded': 'recorded by the investigation',
        'response_source_analyst': 'added by the analyst',
        'response_source_gap': 'from what is still open',
        "appendix": "8. Appendix",
        "answers": "Answers to the Investigation Questions",
        "what_happened": "What happened",
        "why_it_matters": "Why it matters",
        "evidence": "Evidence",
        "when": "When",
        "supported_by": "Supported by",
        "not_answered": "Not answered — no finding was linked to this question.",
        "shape_count": "The question asks for a number; the answer states none.",
        "shape_named": "The question asks which items; the answer names none.",
        "overview_answer": "Overview drawn from all findings — no finding was linked to this question specifically.",
        "answer_parts_heading": "Parts of the request",
        "answer_part_answered": "answered",
        "answer_part_linked": "answered through the linked finding, no value read from it",
        "refines_finding": "Refines",
        "refined_by_finding": "Refined by",
        "answer_part_limited": "not determined",
        "answer_part_open": "open",
        "relevance_answer": "Drawn from the findings that speak to this question — the task was still open when the report was written.",
        "no_questions": "No investigation questions were recorded for this case.",
        "summary": "Summary",
        "assessment": "Assessment",
        "confidence": "Confidence",
        "supporting_evidence": "Supporting Evidence",
        "trace": "Trace",
        "host": "Host",
        "mitre": "MITRE",
        "finding_id": "Finding ID",
        "statement": "Statement",
        "correlated": "correlated",
        "unresolved": "unresolved",
        "projection_note": (
            "Projection from Current Investigation State. Not a source of truth."
        ),
        "key_findings_headers": "ID | Confidence | Host | Statement",
        "no_gaps": "No material evidence gaps recorded on current beliefs.",
        "no_conflicts": "No open Conflict Findings in Current Investigation State.",
        "stale_section": "Section stale — awaiting regeneration.",
        "missing_section": "Section not yet generated from Current Investigation State.",
    },
    "de": {
        "report_title": "Forensischer Untersuchungsbericht",
        "toc": "Inhaltsverzeichnis",
        "exec_summary": "1. Zusammenfassung",
        "scope_evidence": "2. Umfang und Beweismittel",
        "key_findings": "3. Wesentliche Erkenntnisse",
        "detailed_findings": "4. Detaillierte Erkenntnisse",
        "timeline": "5. Angriffszeitlinie",
        "gaps": "6. Beweislücken und offene Fragen",
        "recommendations": "7. Empfehlungen",
        'indicators': 'Indikatoren',
        'ind_frame_incident': 'Rahmen: Vorfall auf den Systemen des Eigentümers. Angreifer-Zeilen sind Sperr- und Suchpunkte; die eigenen Systeme des Eigentümers stehen unter Umfang, nie als Sperrpunkte. Vor dem Sperren die Zugehörigkeit prüfen.',
        'ind_frame_subject': 'Rahmen: Untersuchung des Geräts der beschuldigten Person. Es gibt keine Angreiferseite zum Sperren; die Zeilen sind die Schlüsselkennungen des Falls, und bei Anbietern gehaltene Ressourcen tragen ein Sicherungsersuchen.',
        'ind_counts': '{total} typisierte Indikator(en) ({uses}); {affected} eigene(s) System(e) in den Befunden benannt; {review} aus dem Wortlaut abgeleitete(r) Kandidat(en) vor Verwendung zu prüfen.',
        'ind_none': 'Kein typisierter Indikator wurde aufgezeichnet; {review} aus dem Wortlaut abgeleitete(r) Kandidat(en) warten auf Prüfung.',
        'ind_see': 'Die Liste mit Herkunft steht in `{md}`; dieselben Zeilen für den Import in `{csv}`.',
        'ind_files_missing': 'Die Indikatordateien konnten für diesen Bericht nicht geschrieben werden.',
        'use_block': 'sperren', 'use_contain': 'eindämmen', 'use_hunt': 'suchen', 'use_request': 'anfragen',
        'use_identify': 'identifizieren', 'use_scope': 'Umfang', 'use_review': 'prüfen',
        'response_do_now': 'Sofort',
        'response_none': 'Für diesen Bereich wurden keine Maßnahmen aufgezeichnet.',
        'response_see_estate': 'Estate-weite Maßnahmen stehen im Estate-Bericht.',
        'response_prior_note': "Mit 'aus Vorwissen' markierte Punkte beruhen auf dem, was der Analyst Atlas vor der Auswertung mitgeteilt hat, nicht auf Befunden.",
        'response_examination_note': "Dieser Fall ist eine nachträgliche Untersuchung. Die Pflichten des Eigentümers bleiben bestehen: Jede Maßnahme unten gilt für noch betriebene Systeme und nur, soweit der Eigentümer sie nicht bereits getroffen hat. Eine aus der ATT&CK-Mitigationstabelle abgeleitete Maßnahme ist eine Lehre für den Eigentümer, kein Schritt der ersten Stunde.",
        'response_suspect_note': "Das Gerät oder Abbild gehört der beschuldigten Person: Dem Eigentümer wird keine Bereinigung empfohlen. Soweit eine Maßnahme angezeigt ist, ist sie ein nächster Ermittlungsschritt, ein Sicherungs- oder Rechtshilfeersuchen, die Benachrichtigung eines identifizierten Dritten oder die Eskalation eines andauernden Schadens.",
        'response_owner_assumption': "Der Auftrag sagt nicht, wem das System gehört; die Empfehlungen gehen davon aus, dass der Eigentümer das Opfer ist.",
        'response_state_done': 'erledigt',
        'response_phase_contain': 'Eindämmen',
        'response_phase_eradicate': 'Beseitigen',
        'response_phase_recover': 'Wiederherstellen',
        'response_phase_harden': 'Härten',
        'response_phase_escalate': 'Eskalieren',
        'response_basis_lost': 'Stützt sich auf zurückgezogene Erkenntnisse — vor dem Handeln prüfen',
        'response_phase_investigate': 'Nächste Ermittlungsschritte',
        'response_urgency_now': 'sofort',
        'response_urgency_soon': 'zeitnah',
        'response_urgency_later': 'später',
        'response_scope_host': 'Host',
        'response_scope_network': 'Netzwerk',
        'response_scope_estate': 'Estate',
        'response_source_prior_knowledge': 'aus Vorwissen',
        'response_source_derived': 'aus den Befunden abgeleitet',
        'response_source_recorded': 'von der Untersuchung aufgezeichnet',
        'response_source_analyst': 'vom Analysten ergänzt',
        'response_source_gap': 'aus dem, was noch offen ist',
        "appendix": "8. Anhang",
        "answers": "Antworten auf die Untersuchungsfragen",
        "what_happened": "Was geschehen ist",
        "why_it_matters": "Warum es relevant ist",
        "evidence": "Beweise",
        "when": "Wann",
        "supported_by": "Gestützt auf",
        "not_answered": "Nicht beantwortet — dieser Frage wurde keine Erkenntnis zugeordnet.",
        "shape_count": "Die Frage verlangt eine Zahl; die Antwort nennt keine.",
        "shape_named": "Die Frage verlangt, welche Objekte; die Antwort benennt keines.",
        "overview_answer": "Überblick aus allen Befunden — dieser Frage wurde kein Befund direkt zugeordnet.",
        "answer_parts_heading": "Teile der Anfrage",
        "answer_part_answered": "beantwortet",
        "answer_part_linked": "beantwortet über die verknüpfte Erkenntnis, ohne daraus gelesenen Wert",
        "refines_finding": "Präzisiert",
        "refined_by_finding": "Präzisiert durch",
        "answer_part_limited": "nicht ermittelt",
        "answer_part_open": "offen",
        "relevance_answer": "Aus den Feststellungen abgeleitet, die diese Frage betreffen — die Aufgabe war beim Schreiben des Berichts noch offen.",
        "no_questions": "Für diesen Fall wurden keine Untersuchungsfragen erfasst.",
        "summary": "Zusammenfassung",
        "assessment": "Bewertung",
        "confidence": "Konfidenz",
        "supporting_evidence": "Unterstützende Beweise",
        "trace": "Nachweispfad",
        "host": "Host",
        "mitre": "MITRE",
        "finding_id": "Erkenntnis-ID",
        "statement": "Aussage",
        "correlated": "korreliert",
        "unresolved": "nicht aufgelöst",
        "projection_note": (
            "Projektion aus dem aktuellen Untersuchungszustand. "
            "Keine Quelle der Wahrheit."
        ),
        "key_findings_headers": "ID | Konfidenz | Host | Aussage",
        "no_gaps": "Keine wesentlichen Beweislücken bei aktuellen Erkenntnissen.",
        "no_conflicts": "Keine offenen Konflikte im aktuellen Untersuchungszustand.",
        "stale_section": "Abschnitt veraltet — Regenerierung ausstehend.",
        "missing_section": (
            "Abschnitt noch nicht aus dem aktuellen Untersuchungszustand erzeugt."
        ),
    },
}


def t(key: str, language: str = "en") -> str:
    lang = (language or "en").lower()
    if lang not in GLOSSARY:
        lang = "en"
    return GLOSSARY[lang].get(key) or GLOSSARY["en"].get(key) or key


def section_title(section_id: str, language: str = "en") -> str:
    return t(section_id, language)


def language_instruction(language: str = "en") -> str:
    lang = (language or "en").lower()
    if lang == "de":
        return (
            "Write Summary and Assessment prose in German. "
            "Do NOT translate raw evidence lines, IOCs, paths, usernames, "
            "hostnames, or call_ids."
        )
    return (
        "Write Summary and Assessment prose in English. "
        "Do NOT invent or paraphrase raw evidence lines."
    )
