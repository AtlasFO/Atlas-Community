"""IOC catalog: what gets listed, and whether the line is true.

Every case here is a misreading the engine could make —
an IOC list is only useful if a responder can trust each line without going
back to the claim, so the assertions are about truthfulness, not shape.
"""
import json
import re

import pytest

from core.ioc_catalog import (
    Ioc, build_catalog, grouped, render_markdown, _candidates, _explain,
    _owns_action, _same_clause, adversary_tool_terms, ATTACKER_ACCOUNT,
    _ACTION_PHRASES,
)

# The identities the fixtures below invent. The guard at the end of the
# module checks that none of them reaches core/ioc_catalog.py's logic.
HOST = "FILESRV01"
ACCOUNT = "tempadmin"
CREATOR = "jane.doe"
DOMAIN = "EXAMPLE"
RANSOM_EXT = ".locked"
DROPPED_TOOL = "toolx"
FIXTURE_IDENTITIES = (HOST, ACCOUNT, CREATOR, DOMAIN, RANSOM_EXT, DROPPED_TOOL)


def _case(tmp_path, *statements):
    """A case directory whose claim graph holds `statements` as beliefs."""
    atlas = tmp_path / ".atlas"
    atlas.mkdir(parents=True, exist_ok=True)
    nodes = {
        f"C{i:04d}": {
            "id": f"C{i:04d}", "statement": s, "confidence": "LIKELY",
            "host": HOST, "input_call_ids": [i],
        }
        for i, s in enumerate(statements, start=1)
    }
    (atlas / "claim_graph.json").write_text(json.dumps({"nodes": nodes}))
    return tmp_path


def _rows(catalog):
    """Every row the catalog derived: the actionable typed rows, the
    prose-derived review rows and the own assets. A belief's wording yields
    review rows; only a typed row is a block or hunt item."""
    return (list(catalog.get("iocs") or []) + list(catalog.get("review") or [])
            + list(catalog.get("affected_assets") or []))


def _values(catalog, category=None):
    return {i["value"].lower() for i in _rows(catalog)
            if category is None or i["category"] == category}


def _by_value(catalog, value):
    return next(i for i in _rows(catalog) if i["value"].lower() == value.lower())


# ── extraction: what is a principal ──────────────────────────────────────

def test_domain_qualified_user_yields_the_principal_not_the_domain(tmp_path):
    """`user EXAMPLE\\jane.doe` names one person, not a machine."""
    cat = build_catalog(_case(
        tmp_path,
        f"New local account '{ACCOUNT}' was created on {HOST} by domain "
        f"user {DOMAIN}\\\\{CREATOR}, a covert persistence mechanism."))
    accounts = _values(cat, "account")
    assert CREATOR in accounts
    assert DOMAIN.lower() not in accounts


@pytest.mark.parametrize("statement, ghost", [
    ("This is a covert account creation by a domain user on the fileserver, "
     "used by the attacker for persistence.", "creation"),
    (f"The attacker attempted logon targeting {HOST}\\\\Guest account via "
     "explorer.exe during the intrusion.", "via"),
    ("The attacker encrypted user data across the share.", "data"),
])
def test_ordinary_prose_after_account_is_not_a_principal(tmp_path, statement,
                                                         ghost):
    """A bare English word after "account"/"user" is the next word, not a name."""
    assert ghost not in _values(build_catalog(_case(tmp_path, statement)))


def test_quoted_lowercase_name_still_extracted(tmp_path):
    """The gate must not cost us real lowercase account names."""
    cat = build_catalog(_case(
        tmp_path,
        f"New local account '{ACCOUNT}' was created by the attacker on "
        f"{HOST} as a persistence mechanism."))
    assert ACCOUNT in _values(cat, "account")


def test_a_digit_writes_a_name(tmp_path):
    """'backdoor7' is written as a name: English words carry no digits."""
    cat = build_catalog(_case(
        tmp_path,
        "New local account backdoor7 was created by the attacker on "
        f"{HOST} as a persistence mechanism."))
    assert "backdoor7" in _values(cat, "account")


# ── attribution: whose verb is it ────────────────────────────────────────

def test_creator_is_not_described_as_created(tmp_path):
    """She did the creating; the account is what was created."""
    cat = build_catalog(_case(
        tmp_path,
        f"New local account '{ACCOUNT}' (SID S-1-5-21-1) was created on "
        f"{HOST} on 2031-02-04 by domain user "
        f"{DOMAIN}\\\\{CREATOR}, a covert persistence mechanism."))
    assert "created" in _by_value(cat, ACCOUNT)["explanation"]
    assert "created" not in _by_value(cat, CREATOR)["explanation"]


def test_parenthetical_verb_does_not_reach_across_the_aside(tmp_path):
    """`(created by X)` is about the created account — Guest merely
    appears later."""
    cat = build_catalog(_case(
        tmp_path,
        f"The '{ACCOUNT}' account on {HOST} (created by {CREATOR}) "
        "attempted logon using explicit credentials targeting "
        f"{HOST}\\\\Guest account. This was a lateral movement attempt."))
    assert "created" not in _by_value(cat, "guest")["explanation"]


def test_same_clause_rejects_only_across_a_parenthesis():
    text = f"{ACCOUNT} (created by jroe) targeted Guest"

    def span(word):
        start = text.index(word)
        return (start, start + len(word))
    trigger = span("created")
    assert _same_clause(text, span(ACCOUNT), trigger) is False     # outside
    assert _same_clause(text, span("jroe"), trigger) is True       # inside
    assert _same_clause(text, span(ACCOUNT), span("Guest")) is True  # no paren between


def test_substring_variants_do_not_rob_each_other(tmp_path):
    """`psexec` and `psexec64.exe` are one tool written twice, not rivals."""
    statement = (f"PsExec64.exe found in C:\\\\Users\\\\{ACCOUNT}\\\\Downloads "
                 "was used by the attacker for lateral movement.")
    cat = build_catalog(_case(tmp_path, statement))
    tools = {i["value"].lower(): i["explanation"] for i in _rows(cat)}
    assert "psexec64.exe" in tools
    for name, explanation in tools.items():
        assert explanation, f"{name} lost its explanation to a substring rival"


def test_owns_action_prefers_the_nearer_entity():
    pattern = next(p for p, ph in _ACTION_PHRASES
                   if ph == "created during the incident")
    text = "account alpha was created here, and later bravo did something"
    assert _owns_action(text, pattern, "alpha", ["bravo"]) is True
    assert _owns_action(text, pattern, "bravo", ["alpha"]) is False


# ── role gating: what can truthfully be said ─────────────────────────────

def test_account_is_never_executed_or_found_in_a_folder():
    """Phrases about files must not be said of a principal."""
    statement = ("setup.exe was executed from "
                 f"C:\\\\Users\\\\{ACCOUNT}\\\\Downloads by the attacker.")
    explanation = _explain(ACCOUNT, statement, ATTACKER_ACCOUNT, [])
    assert "executed" not in explanation
    assert "download" not in explanation.lower()


def test_stock_os_binary_is_not_attacker_tooling(tmp_path):
    """explorer.exe is the mechanism in the sentence, not an indicator."""
    cat = build_catalog(_case(
        tmp_path,
        f"The '{ACCOUNT}' account attempted logon using explicit credentials "
        f"targeting {HOST}\\\\Guest account via explorer.exe (PID 0x1A4)."))
    assert "explorer.exe" not in _values(cat)


def test_lolbin_still_surfaces_when_behaviour_says_so(tmp_path):
    """Dual-use suppression must not blind us to malicious use."""
    cat = build_catalog(_case(
        tmp_path,
        "The attacker used rundll32.exe to execute a malicious payload "
        "dropped in C:\\\\Users\\\\Public\\\\, a credential theft attempt."))
    assert "rundll32.exe" in _values(cat)


def test_explanation_never_repeats_itself():
    statement = ("RemoteX was installed as a service and installed on "
                 f"{HOST} by the attacker.")
    parts = _explain("remotex", statement, "attacker_tool", []).split(", ")
    assert len(parts) == len(set(parts))


# ── the deliverable ──────────────────────────────────────────────────────

def test_every_listed_ioc_cites_a_claim(tmp_path):
    """The list is checkable or it is worthless."""
    cat = build_catalog(_case(
        tmp_path,
        "Mimikatz credential-dumping driver (driverx) installed as kernel driver service "
        f"on {HOST}. ImagePath: C:\\\\Users\\\\{ACCOUNT}\\\\Downloads\\\\driverx.sys. "
        "This indicates credential dumping by an attacker.",
        f"Files with the {RANSOM_EXT} extension were encrypted across the share "
        "by the ransomware."))
    assert _rows(cat)
    for ioc in _rows(cat):
        assert ioc["claim_ids"], f"{ioc['value']} cites no claim"
        assert ioc["explanation"], f"{ioc['value']} has no explanation"
        assert ioc["confidence"] == "LIKELY"   # never exceeds the belief


def test_absence_claims_yield_nothing(tmp_path):
    cat = build_catalog(_case(
        tmp_path, f"No mimikatz.exe was found anywhere on {HOST}."))
    assert "mimikatz.exe" not in _values(cat)


def test_missing_or_broken_graph_is_an_empty_catalog(tmp_path):
    """The IOC view must never be able to break the dashboard."""
    assert build_catalog(tmp_path / "nope")["total"] == 0
    atlas = tmp_path / ".atlas"
    atlas.mkdir()
    (atlas / "claim_graph.json").write_text("{not json")
    assert build_catalog(tmp_path)["total"] == 0


def test_grouped_drops_empty_groups_and_keeps_order(tmp_path):
    cat = build_catalog(_case(
        tmp_path,
        "The attacker connected to relay.evil.example.com and encrypted "
        f"files with the {RANSOM_EXT} extension across the share."))
    titles = [t for t, _rows in grouped(cat)]
    assert titles == sorted(set(titles), key=titles.index)
    assert all(rows for _t, rows in grouped(cat))


def test_markdown_states_the_boundary_when_empty(tmp_path):
    md = render_markdown(build_catalog(_case(tmp_path, "")), case_id="X")
    assert "recorded beliefs" in md


def test_seed_lexicon_is_present_without_the_brain():
    assert "mimikatz" in adversary_tool_terms()


# ── the deliverable file ─────────────────────────────────────────────────

def test_write_ioc_report_lands_under_reports(tmp_path):
    from core.ioc_catalog import write_ioc_report
    case = _case(tmp_path, f"The attacker installed mimikatz on {HOST} to "
                           "dump credentials.")
    path = write_ioc_report(case)
    assert path and path.endswith("_iocs.md")
    text = __import__("pathlib").Path(path).read_text()
    assert "mimikatz" in text and "## Review before use" in text
    assert "Verify ownership before deploying a block item." in text
    assert (__import__("pathlib").Path(path).with_suffix(".csv")).is_file()


def test_write_ioc_report_never_raises(tmp_path):
    """A broken indicator list must not be able to cost a case its report."""
    from core.ioc_catalog import write_ioc_report
    assert write_ioc_report(tmp_path / "does" / "not" / "exist") in ("", None) \
        or True     # returns a path or "", but must not raise


# ── the self-maintaining lexicon ─────────────────────────────────────────

@pytest.fixture
def brain(tmp_path, monkeypatch):
    root = tmp_path / "brain"
    for d in ("wiki/tools", "memory", "logs", "inbox"):
        (root / d).mkdir(parents=True)
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(root))
    return root


BEHAVIOUR_FIND = ("The attacker dropped a malicious credential-theft payload "
                  f"named {DROPPED_TOOL}.exe in C:\\\\Users\\\\{ACCOUNT}\\\\Downloads\\\\ "
                  f"and executed it on {HOST}.")


def test_behaviour_discovered_tool_enters_the_lexicon(tmp_path, brain):
    """The routine that keeps the lexicon from rotting: no LLM, no reviewer."""
    from core.ioc_catalog import capture_adversary_tools
    case = _case(tmp_path / "c1", BEHAVIOUR_FIND)
    assert DROPPED_TOOL not in adversary_tool_terms()
    assert capture_adversary_tools(case, "CASE-E")
    assert DROPPED_TOOL in adversary_tool_terms()


def test_lexicon_does_not_cite_itself(tmp_path, brain):
    """A name flagged only because the lexicon knew it teaches nothing."""
    from core.ioc_catalog import capture_adversary_tools
    case = _case(tmp_path / "c2",
                 f"Mimikatz was used by the attacker on {HOST}.")
    written = capture_adversary_tools(case, "CASE-E")
    assert not any("mimikatz" in w for w in written)


def test_repeat_sighting_corroborates_rather_than_duplicates(tmp_path, brain):
    from core.ioc_catalog import capture_adversary_tools
    case = _case(tmp_path / "c3", BEHAVIOUR_FIND)
    capture_adversary_tools(case, "CASE-E")
    capture_adversary_tools(case, "CASE-F")
    notes = list((brain / "wiki" / "tools").glob("adversary-tool-*.md"))
    assert len(notes) == 1
    text = notes[0].read_text()
    assert "CASE-E" in text and "CASE-F" in text
    # ...and re-running the same case adds nothing.
    assert capture_adversary_tools(case, "CASE-F") == []


def test_ordinary_software_never_enters_the_lexicon(tmp_path, brain):
    from core.ioc_catalog import capture_adversary_tools
    case = _case(tmp_path / "c4",
                 "The attacker used powershell.exe and 7z.exe to stage a "
                 f"malicious archive for exfiltration from {HOST}.")
    for note in capture_adversary_tools(case, "CASE-E"):
        assert "powershell" not in note and "7z" not in note


def test_capture_is_silent_when_there_is_no_brain(tmp_path, monkeypatch):
    from core.ioc_catalog import capture_adversary_tools
    monkeypatch.setenv("ATLAS_BRAIN_ROOT", str(tmp_path / "nope"))
    assert capture_adversary_tools(_case(tmp_path / "c5", BEHAVIOUR_FIND)) == []


def test_case_specific_identities_never_reach_the_brain(tmp_path, brain):
    """Usernames and hostnames are facts about *this* case, not knowledge.

    A tool name generalises to the next investigation; an account and a
    host name do not, and writing them into the Brain would leak a case's
    identities into every later run's lexicon.
    """
    from core.ioc_catalog import capture_adversary_tools, build_catalog
    case = _case(
        tmp_path / "leak",
        f"The attacker created the local account '{ACCOUNT}' on {HOST} and "
        f"dropped a malicious credential-theft payload named {DROPPED_TOOL}.exe "
        f"in C:\\\\Users\\\\{ACCOUNT}\\\\Downloads\\\\ on that host.")
    # The catalog itself does surface the account and host — that is the point
    # of a per-case IOC list.
    catalog = build_catalog(case)
    roles = {i["role"] for i in _rows(catalog)}
    assert "attacker_account" in roles

    capture_adversary_tools(case, "CASE-E")
    written = "\n".join(p.read_text()
                        for p in (brain / "wiki" / "tools").rglob("*.md"))
    assert DROPPED_TOOL in written           # the tool generalises
    assert ACCOUNT not in written            # the account does not
    assert HOST.lower() not in written.lower()


# ── none of this may be fitted to one engagement ─────────────────────────
#
# Every case below uses hosts, users, families and layouts unlike the
# fixtures above. A rule that only works on the sample it was written from
# is not a rule.

@pytest.mark.parametrize("name", [
    "quarterly.xlsx.WNCRY", "notes.docx.locky", "photo.jpg.crab",
    "db.sqlite.encrypted_by_thanos", "report.pdf.5ss5c", "x.mp4.deadbolt",
])
def test_unseen_ransomware_families_read_as_files(name):
    """Judged by the extension underneath, so no family list is needed."""
    from core.ioc_catalog import _looks_like_file
    assert _looks_like_file(name.lower())


@pytest.mark.parametrize("name", ["john.roe", "a.roe", "j.doe"])
def test_person_names_still_are_not_files(name):
    from core.ioc_catalog import _looks_like_file
    assert not _looks_like_file(name.lower())


def test_encrypted_file_survives_end_to_end(tmp_path):
    cat = build_catalog(_case(
        tmp_path / "rw",
        "The ransomware encrypted the share, including quarterly.xlsx.WNCRY "
        "dropped by the attacker in C:\\\\Users\\\\a.roe\\\\Documents\\\\."))
    assert any("quarterly" in v for v in _values(cat))


@pytest.mark.parametrize("binary", [
    "taskmgr.exe", "shutdown.exe", "CredentialUIBroker.exe", "mstsc.exe",
    "notepad.exe", "OneDriveSetup.exe", "SearchIndexer.exe", "wermgr.exe",
])
def test_bare_execution_never_makes_an_indicator(tmp_path, binary):
    """No list of OS binaries — "the attacker ran X" is simply not evidence."""
    cat = build_catalog(_case(
        tmp_path / binary.replace(".", "_"),
        f"UserAssist on WKSTN-4471 shows tools executed by the attacker on "
        f"2031-02-04: {binary} at 11:02, and several others."))
    assert binary.lower() not in _values(cat)


def test_corroborated_binary_still_lists(tmp_path):
    """The same rule must not blind us: staging location is corroboration."""
    cat = build_catalog(_case(
        tmp_path / "corrob",
        "The attacker dropped toolx2.exe in "
        "C:\\\\Users\\\\a.roe\\\\Downloads\\\\ on WKSTN-4471 and ran it."))
    assert "toolx2.exe" in _values(cat)


@pytest.mark.parametrize("rel, host, expect", [
    ("evidence/PROD-SQL-02/C/Windows/x.evtx", "PROD-SQL-02", True),
    ("analysis/prod-sql-02_security.csv", "PROD-SQL-02", True),
    ("exports/node7_System.evtx", "node7", True),
    ("evidence/laptop-hr-9/x.evtx", "PROD-SQL-02", False),
    ("analysis/hostile_data.csv", "host", False),
])
def test_host_attribution_needs_no_naming_convention(rel, host, expect):
    """An earlier version guessed from name prefixes ("srv", "dc", "ws")."""
    from core.ioc_pivots import _source_is_about_host
    assert _source_is_about_host(rel, host) is expect


def test_no_case_identifiers_are_baked_into_the_module():
    """A guard against fitting the tool to whatever case is on the desk: no
    identity the fixtures of this module invent may reach its *logic*."""
    import pathlib
    src = pathlib.Path("core/ioc_catalog.py").read_text()
    # Docstrings and comments are stripped; the rule is about the logic.
    code = re.sub(r'"""(?:.|\n)*?"""', "", src)
    code = "\n".join(line for line in code.splitlines()
                      if not line.lstrip().startswith("#")).lower()
    for token in FIXTURE_IDENTITIES:
        assert token.lower() not in code, f"{token!r} is case-specific, not knowledge"


def test_a_value_the_belief_calls_benign_is_not_an_indicator(tmp_path):
    """A belief that names a value to dismiss it attributes nothing: the
    version-shaped folder and the vendor's server stay out, the address the
    same beliefs say the attacker used stays in."""
    case = _case(
        tmp_path,
        "The address 1.0.0.1 in the listings is a PowerShell module version "
        "folder, not an attacker indicator.",
        "The attacker connected to 10.9.8.7 and exfiltrated the archive.",
        "Traffic to 5.6.7.8 is benign: it is the vendor's update server.",
    )
    values = _values(build_catalog(case), "ip")
    assert "1.0.0.1" not in values and "5.6.7.8" not in values
    assert "10.9.8.7" in values


class TestNegatedWordsAreNotAssertions:
    """The catalog read an attack word the analyst negated as evidence of
    attack: a ruling that cleared a value attributed it on the strength of
    the very word being denied. A negated attack word describes no attack;
    a negated dismissal ("does not appear benign", "cannot rule out") is
    the analyst's suspicion in the analyst's own words."""

    STATEMENT = ("Recurring URLs http://www.w3.org/tr/rec-html40 and "
                 "http://schemas.microsoft.com/office/2004/12/omml are XML "
                 "namespace/DOCTYPE identifiers embedded in Office .docx/.pptx "
                 "files (Word/PowerPoint schema references), not network "
                 "exfiltration channels. Seen in several tool calls.")

    def test_a_namespace_ruling_attributes_nothing(self, tmp_path):
        assert not _values(build_catalog(_case(tmp_path, self.STATEMENT)))

    @pytest.mark.parametrize("ruling", [
        "update.googleapis.com is Chrome's updater, not C2.",
        "https://login.live.com/oauth20 is the Office sign-in endpoint, not an "
        "exfiltration channel.",
        "telemetry.vendor.example is the AV agent's cloud lookup, not "
        "command-and-control.",
        "relay.vendor.example was not blocked and is benign; it connected to the "
        "update API.",
        "No evidence of exfiltration to mega.evil.example was found.",
        "The agent did not alert or exfiltrate anything to relay.vendor.example.",
    ])
    def test_a_clearing_ruling_attributes_nothing(self, tmp_path, ruling):
        assert not _values(build_catalog(_case(tmp_path, ruling)))

    @pytest.mark.parametrize("statement, value", [
        ("did not delete the logs but exfiltrated data to https://drop.example.net/up",
         "https://drop.example.net/up"),
        ("beacon traffic to https://c2.example.net/x was not blocked", "https://c2.example.net/x"),
        ("https://upd.example.net/x is not a legitimate update server; it is the C2",
         "https://upd.example.net/x"),
        ("The implant downloaded its payload from "
         "http://schemas.microsoft.com/office/2004/12/omml",
         "http://schemas.microsoft.com/office/2004/12/omml"),
        ("https://odd.example.net/x does not appear to be benign; it beaconed every 60 seconds.",
         "https://odd.example.net/x"),
        ("https://odd.example.net/x doesn't look benign; it beaconed every 60 seconds.",
         "https://odd.example.net/x"),
        ("We cannot rule out that update-check.evil.example.net is used for C2.",
         "update-check.evil.example.net"),
        ("The analyst could not rule out beaconing to cdn-sync.evil.example.net.",
         "cdn-sync.evil.example.net"),
        # a negated dismissal alone is the analyst's suspicion: listed, on purpose
        ("https://odd.example.net/x does not appear benign.", "https://odd.example.net/x"),
        # the narrow negator stops at a conjunction; a typographic apostrophe negates
        ("The file was not blocked and exfiltrated data to https://drop.example.net/up",
         "https://drop.example.net/up"),
        ("https://odd.example.net/x isn\u2019t benign; it beaconed every 60 seconds.",
         "https://odd.example.net/x"),
        # a binary named like a Recycle Bin record is still a binary
        ("The attacker's malicious $Install.exe was executed from the Recycle Bin",
         "install.exe"),
    ])
    def test_an_assertion_is_attributed(self, tmp_path, statement, value):
        assert value in _values(build_catalog(_case(tmp_path, statement))), statement

    def test_an_executable_is_never_suppressed_as_a_parsed_artifact(self):
        from core.ioc_catalog import _suppressed
        assert _suppressed("file", "$iabcdef.docx")      # a Recycle Bin record is evidence
        assert not _suppressed("file", "$install.exe")   # a binary named like one is not



# ── hygiene: what a dotted token is ──────────────────────────────────────

@pytest.mark.parametrize("token, kind", [
    ("ccsetup504.exe-6ba2f6a1.pf", "file"),      # prefetch name: extension inside a label, .pf is a TLD too
    ("6.2.0.2962.exe", "file"),
    ("mailbox.ost", "file"),
    ("readme.md", "file"),                        # .md is a delegated TLD; the extension wins
    ("archive.zip", "file"),
    ("alt.binaries.warez", "newsgroup"),          # hierarchy prefix, last label no TLD
    ("alt.binaries.pictures", "domain"),          # a TLD last label without a cue stays a domain
    ("news.example.net", "domain"),               # a news server is a server
    ("de.example.com", "domain"),
    ("corp.local", "internal"),
    ("intra.example.lan", "internal"),
    ("a.roe", ""),
    ("10.0.0.1", ""),
])
def test_dotted_tokens_are_files_domains_internal_names_or_newsgroups(token, kind):
    from core.ioc_catalog import _dotted_kind
    assert _dotted_kind(token) == kind


def test_a_group_cue_governs_the_whole_sentence_past_a_colon(tmp_path):
    from core.ioc_catalog import _candidates
    cands = _candidates(
        "The subscribed newsgroups cover one topic: alt.hobby.radio, alt.binaries.warez, "
        "alt.binaries.pictures, comp.security.misc. The news server was news.example.net.",
        set())
    assert ("domain", "news.example.net") in cands
    assert not any(v.startswith(("alt.", "comp.")) for _c, v in cands)


def test_server_words_are_not_group_cues(tmp_path):
    from core.ioc_catalog import _candidates
    cands = _candidates(
        "Mail settings: NNTP (news) server news.example.net, SMTP server smtp.example.net.", set())
    assert {v for c, v in cands if c == "domain"} == {"news.example.net", "smtp.example.net"}


def test_an_email_needs_a_real_top_level_domain(tmp_path):
    from core.ioc_catalog import _candidates
    cands = _candidates("Mailbox file j.roe@example.net.ost holds mail from spy@example.net.", set())
    emails = {v for c, v in cands if c == "email"}
    assert emails == {"spy@example.net"}


def test_a_special_use_name_is_never_an_account_or_infrastructure(tmp_path):
    cat = build_catalog(_case(
        tmp_path,
        "The attacker logged on to the domain CORP.LOCAL as CORP.LOCAL\\\\Administrator "
        "from 203.0.113.9 and exfiltrated the share."))
    assert "corp.local" not in _values(cat)
    assert "203.0.113.9" in _values(cat)


def test_a_lexicon_term_matches_whole_tokens_only(tmp_path):
    from core.ioc_catalog import _has_term
    assert _has_term("mimikatz", "mimikatz.exe was dropped")
    assert not _has_term("beacon", "https beaconing to the relay was observed")


def test_a_lexicon_name_alone_never_promotes(tmp_path):
    """The name only raises a corroborated file to a tool."""
    listed = build_catalog(_case(
        tmp_path / "listing",
        "The software inventory on WKSTN-4471 lists mimikatz.exe among 214 installed programs."))
    assert "mimikatz.exe" not in _values(listed)
    used = build_catalog(_case(
        tmp_path / "used",
        "The attacker ran mimikatz.exe from C:\\\\Users\\\\Public\\\\ to dump credentials, "
        "a malicious credential theft."))
    assert _by_value(used, "mimikatz.exe")["role"] == "attacker_tool"
