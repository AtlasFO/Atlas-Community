"""Typed values: what a part asks for, what a statement carries, and which
clause binds the two."""
from __future__ import annotations

import pytest

from core import answer_values as av


class TestTypeWords:
    @pytest.mark.parametrize("part, kind", [
        ("MAC", "mac"), ("IP address", "ip"), ("SMTP address", "email"), ("web-mail address", "email"),
        ("mail identities", "email"), ("install date", "datetime"), ("timezone", "zone"),
        ("operating system", "os"), ("accounts", "account"), ("computer name", "host"),
        ("the delivery IP", "ip"), ("the C2 IP", "ip"), ("whether it is recoverable", "yes_no"),
        ("how many accounts", "count"), ("which card was in use", "list"), ("family", "name"),
        ("serial number of the medium", "identifier"), ("the on-disk path", "path"),
        ("prove the connection between the key and the traffic", "relation"),
        ("Zeitzone", "zone"), ("wann", "datetime"), ("welche Konten", "account"),
    ])
    def test_the_most_specific_word_names_the_kind(self, part, kind):
        assert av.type_for(part) == kind

    def test_a_bare_address_names_no_kind(self):
        assert av.type_for("address") is None
        assert av.type_for("the artefact that binds") is None or av.type_for("the artefact that binds") == "path"

    def test_the_qualifier_is_the_part_beyond_its_kind(self):
        assert av.qualifier("the delivery IP") == {"delivery"}
        assert av.qualifier("install date") == {"install"}
        assert av.qualifier("the C2 IP") == {"c2"}
        assert av.qualifier("with timestamp") == set()
        assert av.qualifier("accounts") == set()


class TestRecognisers:
    def test_bare_hostnames_and_known_hosts(self):
        text = "DC01 and DESKTOP-SDN1RPT and N-1A9ODN6ZXK4LQ; claim C0009; CVE-2021-1234; T1059.001; citadel"
        got = {v for v, _ in av.values(text, "host", known_hosts=["Citadel"])}
        assert {"DC01", "DESKTOP-SDN1RPT", "N-1A9ODN6ZXK4LQ", "citadel"} <= got
        assert not {"C0009", "CVE-2021", "T1059"} & got

    def test_accounts_in_their_written_forms(self):
        text = ("The only real user profile is 'Mr. Smith'; local account jsmith; CORP\\a.roe; "
                "S-1-5-21-1-2-3-1002; account creation by Administrator; Greg Schardt (RID 1003)")
        got = {v for v, _ in av.values(text, "account")}
        # a bare lower-case word after "account" is prose unless the statement
        # writes it as a principal somewhere ("named X" does)
        assert {"Mr. Smith", "CORP\\a.roe", "S-1-5-21-1-2-3-1002", "Administrator", "Greg Schardt"} <= got
        assert "jsmith" not in got
        assert "jsmith" in {v for v, _ in av.values("the local account named jsmith owns the laptop", "account")}
        assert "creation" not in got

    def test_dates_with_and_without_a_time_and_word_dates(self):
        text = "installed 2004-08-19; window 2018-03-27 to 2018-04-06; on 22 March 2015 and March 22, 2015 08:00; 22. März 2015"
        got = [v for v, _ in av.values(text, "datetime")]
        assert got[:3] == ["2004-08-19", "2018-03-27", "2018-04-06"]
        assert "22 March 2015" in got and "March 22, 2015" in got and "22. März 2015" in got

    def test_domains_and_urls_but_not_file_names(self):
        got = {v for v, _ in av.values("beacons to c2.example.com and http://evil.local/x; file example.exe; C137.LOCAL", "domain")}
        assert {"c2.example.com", "http://evil.local/x", "C137.LOCAL"} <= got
        assert "example.exe" not in got

    def test_macs_zones_os_and_identifiers(self):
        assert [v for v, _ in av.values("NIC MAC 0010a4933e09 (00:10:A4:93:3E:09) build 6.3.9600.17031", "mac")] == ["0010a4933e09", "00:10:A4:93:3E:09"]
        assert [v for v, _ in av.values("Eastern Standard Time, Bias 300, UTC-5", "zone")] == ["Eastern Standard Time", "Bias 300", "UTC-5"]
        assert av.values("runs Windows XP Professional SP1; Windows Server 2012 R2 (build 6.3.9600.17031)", "os")[0][0] == "Windows XP Professional SP1"
        got = {v for v, _ in av.values("RM#1 serial 4C530012450531101593, volume serial 1A2B-3C4D, {12345678-1234-1234-1234-123456789abc}", "identifier")}
        assert {"4C530012450531101593", "1A2B-3C4D", "{12345678-1234-1234-1234-123456789abc}"} <= got

    def test_a_count_is_the_number_beside_the_counted_noun(self):
        assert av.bind("how many accounts were created", "count",
                       "On 2015-03-22 the user created 3 new local accounts on informant-PC (EID 4720).")[0] == "3"
        assert av.bind("how many accounts were created", "count",
                       "On 2015-03-22 accounts were reviewed; the record 4720 shows nothing.")[0] is None


class TestBinding:
    NET = "Network: delivery IP is 194.61.24.102 (external, attacker host 'kali'); C2 IP is 10.90.90.90 (internal)"
    NIC = "Network identity of the notebook during the Look@LAN setup: IP address 192.168.1.111, NIC MAC 0010a4933e09 on the Xircom card"

    def test_each_part_takes_the_value_of_its_own_clause(self):
        assert av.bind("the delivery IP", "ip", self.NET)[0] == "194.61.24.102"
        assert av.bind("the C2 IP", "ip", self.NET)[0] == "10.90.90.90"

    def test_the_nearest_value_in_a_comma_joined_clause(self):
        assert av.bind("IP", "ip", self.NIC)[0] == "192.168.1.111"
        assert av.bind("MAC", "mac", self.NIC)[0] == "0010a4933e09"

    def test_a_part_without_a_qualifier_reads_the_first_sentence_only(self):
        st = ("Initial access to DC01 via RDP brute force from external IP 194.61.24.102 at 2020-09-19 02:19:13 UTC. "
              "Later at 2020-09-20 01:00 UTC more.")
        assert av.bind("with timestamp", "datetime", st)[0] == "2020-09-19 02:19:13 UTC"
        assert av.bind("operating system", "os", "The Dell CPi notebook runs Windows XP (NTFS volume, offset sector 63).")[0] == "Windows XP"

    def test_a_value_of_the_right_kind_in_the_wrong_clause_does_not_answer(self):
        st = ("Device and system baseline: the seized evidence is an EnCase image of the notebook. "
              "Acquired 2004-09-20 10:00 UTC by the examiner.")
        assert av.bind("install date", "datetime", st) == (None, "")
        assert av.bind("install date", "datetime",
                       "Windows XP was installed on 2004-08-19 22:48:27 UTC (SOFTWARE InstallDate).")[0] == "2004-08-19 22:48:27 UTC"

    def test_qualifiers_match_by_stem_and_short_tokens_count(self):
        assert av.bind("computer name", "host", "The computer name is N-1A9ODN6ZXK4LQ and the primary domain is unknown.")[0] == "N-1A9ODN6ZXK4LQ"
        assert av.bind("timezone", "zone", "The notebook's time zone is Central Standard Time (Bias 360).")[0] == "Central Standard Time"

    def test_non_value_kinds_bind_nothing(self):
        assert av.bind("whether it is recoverable", "yes_no", "Yes, the files are recoverable.") == (None, "")
        assert av.bind("prove the connection", "relation", "They match.") == (None, "")


class TestPrintedValuePrecision:
    """What the report prints as a part's value must be the value: whole
    file names, times with their zone, the machine's own name, and each
    sibling part's own value."""

    def test_file_names_with_spaces_are_taken_whole(self):
        text = ('The Desktop holds "The Long Memo.docx" (816KB), "Planning.docx" and "Operation Second '
                'Draft.pptx"; the recipe at C:\\Share\\Secret\\Family Recipe.txt (512 bytes) and Board_Notes.txt')
        got = [v for v, _ in av.values(text, "path")]
        assert got == ["The Long Memo.docx", "Planning.docx", "Operation Second Draft.pptx",
                       "C:\\Share\\Secret\\Family Recipe.txt", "Board_Notes.txt"]
        unquoted = "The Desktop holds The Long Memo.docx, Planning.docx, Operation Second Draft.pptx and TRAVEL NOTES.docx."
        assert [v for v, _ in av.values(unquoted, "path")] == [
            "The Long Memo.docx", "Planning.docx", "Operation Second Draft.pptx", "TRAVEL NOTES.docx"]
        assert av.bind("the recipe file", "path", "Data theft: the recipe file C:\\Share\\Secret\\Family Recipe.txt was opened at 09:15 UTC.")[0] == "C:\\Share\\Secret\\Family Recipe.txt"

    def test_a_time_keeps_its_zone_and_utc_wins(self):
        text = "Lateral movement at 2020-09-19 03:36:22 DC01 time (~02:36 UTC, 1h VM clock skew); logon 2020-09-19 02:19:13 UTC"
        got = [v for v, _ in av.values(text, "datetime")]
        assert got[0] == "2020-09-19 02:19:13 UTC" and "2020-09-19 03:36:22 DC01 time" in got
        assert av.bind("when", "datetime", "The attacker moved to the desktop at 2020-09-19 03:36:22 DC01 time (~02:36 UTC).")[0] == "2020-09-19 03:36:22 DC01 time"

    def test_a_host_label_is_the_computer_name_only_when_named_so(self):
        assert av.bind("computer name", "host", "The Dell CPi notebook runs Windows XP (NTFS volume).", known_hosts=["CPi"]) == (None, "")
        assert av.bind("computer name", "host", "The computer name of the CPi notebook is N-1A9ODN6ZXK4LQ.", known_hosts=["CPi"])[0] == "N-1A9ODN6ZXK4LQ"
        assert av.values("host CPi was imaged; computer name CPi", "host", known_hosts=["CPi"], name_part=True)[0][0] == "CPi"
        assert av.values("host CPi was imaged", "host", known_hosts=["CPi"], name_part=True) == []

    def test_sibling_parts_keep_their_sub_kind_words(self):
        assert av.qualifier("SMTP address") == {"smtp"} and av.qualifier("web-mail address") == {"web-mail"}
        assert av.bind("web-mail address", "email", "The user's web-mail address is 7a4o0f8osgs2u@yahoo.com, from the Yahoo cookie.")[0] == "7a4o0f8osgs2u@yahoo.com"
        assert av.bind("web-mail address", "email", "SMTP email address whoknowsme@sbcglobal.net, SMTP server smtp.sbcglobal.net.") == (None, "")
        assert av.bind("SMTP address", "email", "SMTP email address whoknowsme@sbcglobal.net, SMTP server smtp.sbcglobal.net.")[0] == "whoknowsme@sbcglobal.net"

    def test_a_shortcut_never_wins_over_the_file_it_points_to(self):
        st = ("Data theft on FILESRV01: the recipe file at C:\\Share\\Secret\\Family Recipe.txt (512 bytes) was opened at "
              "09:15 UTC; a Recent Items shortcut (C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\Family Recipe.lnk, "
              "MFT 9021) records the open.")
        assert av.bind("the recipe file", "path", st)[0] == "C:\\Share\\Secret\\Family Recipe.txt"
        assert av.bind("the recipe file", "path", st, explicit=True)[0] == "C:\\Share\\Secret\\Family Recipe.txt"
        assert av.bind("the file", "path", "Only the shortcut C:\\Users\\admin\\Recent\\Family Recipe.lnk survives.")[0].endswith(".lnk")


def test_a_value_carrying_the_qualifier_word_wins_over_the_next_value_in_a_list():
    """A multi-word file name starts before the qualifier word it contains;
    ranked by its start alone it would lose to the next name in a comma
    list. The word is the value's own, so the value wins on both paths."""
    from core.answer_values import bind
    clause = ("Recent-items shortcuts on the workstation point at four documents "
              "on the share: Secret Recipe.txt, Board_Notes.txt, Roadmap.txt, Budget.txt.")
    assert bind("the recipe file", "path", clause)[0] == "Secret Recipe.txt"
    assert bind("the recipe file", "path", clause, explicit=True)[0] == "Secret Recipe.txt"
    # a qualifier that names a later value still binds that value
    assert bind("the roadmap file", "path", clause)[0] == "Roadmap.txt"


def test_the_fuller_form_wins_when_both_forms_carry_the_qualifier_word():
    """A conclusion names a file twice, bare and as its full path; both carry
    the qualifier word, and the full path is the more useful answer."""
    from core.answer_values import bind
    clause = "Secret Recipe.txt (C:\\Share\\Secret\\Secret Recipe.txt, 512 bytes, inode 4242) was opened at 09:15 UTC."
    assert bind("the recipe file", "path", clause)[0] == "C:\\Share\\Secret\\Secret Recipe.txt"
    assert bind("the recipe file", "path", clause, explicit=True)[0] == "C:\\Share\\Secret\\Secret Recipe.txt"


def test_a_stop_after_a_title_or_initial_does_not_end_a_clause():
    from core.answer_values import clauses
    text = "The main user of the notebook is Mr. Smith, SID S-1-5-21-1-2-3-1003. The account was last active on 2031-02-04."
    assert [c for c, _o in clauses(text)][0].endswith("S-1-5-21-1-2-3-1003.")
    assert len(clauses("J. Doe logged on. The session ended.")) == 2


@pytest.mark.parametrize("statement, want", [
    ("The main and last user of the notebook is 'Mr. Smith' (a local profile).", "Mr. Smith"),
    ("The main and last user of the notebook is Mr. Smith.", "Mr. Smith"),
    ("The main and last user account on the notebook is Mr. Smith, SID S-1-5-21-1-2-3-1003.", "Mr. Smith"),
    ("The main and last user account on the notebook was MrSmith (display name Mr. Smith).", "MrSmith"),
    # a short qualifier is carried whole: a claim about the main user alone
    # does not answer a part that asks for the main and last user
    ("The main user account on the notebook is MrSmith. The account was last active on 2031-02-04.", None),
    ("The main user account on the notebook is Windows XP's default profile; the last user is unknown.", None),
])
def test_an_account_named_after_a_copula_binds(statement, want):
    from core.answer_values import bind
    assert bind("main and last user", "account", statement)[0] == want


def test_a_spaced_file_name_is_kept_whole_before_a_sentence_final_stop():
    from core.answer_values import bind
    assert bind("the recipe file", "path", "The stolen file was C:\\Share\\Secret\\Family Recipe.txt.")[0] == \
        "C:\\Share\\Secret\\Family Recipe.txt"


def test_a_registered_owner_is_a_name_and_a_netbios_domain_counts_after_its_cue():
    from core.answer_values import bind, type_for
    text = ("System install date is 2031-01-19 (SYSTEM hive InstallDate). The registered owner is Jane Roe "
            "(SOFTWARE hive RegisteredOwner). The primary domain is WS-7A2B (LSA PolPrDmN), the machine's own name.")
    assert type_for("registered owner") == "name"
    assert bind("registered owner", "name", text)[0] == "Jane Roe"
    assert bind("primary domain", "domain", text)[0] == "WS-7A2B"
    assert bind("primary domain", "domain", "The primary domain of the notebook is corp.example.net; DC01 serves it.")[0] == "corp.example.net"


@pytest.mark.parametrize("statement", [
    "The logon type was Network for the session on WS01.",
    "The logon was Interactive and the login was Successful.",
    "The user opened the document titled \"Q3 Budget\" twice.",
    "The account status is Disabled since the incident.",
])
def test_logon_attributes_and_quoted_titles_are_not_accounts(statement):
    from core.answer_values import values
    assert values(statement, "account") == []


def test_a_bare_principal_at_a_sentence_end_keeps_no_stop():
    from core.answer_values import values
    assert ("SQLSvc", 21) in values("The job ran for user SQLSvc.", "account")


@pytest.mark.parametrize("part, kind, text, want", [
    # a plan file, never the notes beside it
    ("the plan documents", "path", "The folder holds Planning.docx, notes.txt and plan_final.pdf.", {"Planning.docx", "plan_final.pdf"}),
    ("the plan documents", "path", "The folder holds Planning.docx, meeting_notes_final_version.txt and plan_final.pdf.", {"Planning.docx", "plan_final.pdf"}),
    ("registered owner", "name", "The registered owner in the SOFTWARE hive is Jane Roe (RegisteredOrganization N/A).", {"Jane Roe"}),
])
def test_a_stem_of_the_qualifier_inside_a_value_ranks_behind_a_whole_word_and_ahead_of_neighbours(part, kind, text, want):
    from core.answer_values import bind
    assert bind(part, kind, text)[0] in want


def test_a_label_before_a_colon_binds_the_value_that_follows():
    from core.answer_values import bind
    assert bind("registered owner", "name", "RegisteredOwner: Jane Roe")[0] == "Jane Roe"
    assert bind("computer name", "host", "ComputerName: WS-7A2B; the machine's own name")[0] == "WS-7A2B"


def test_a_label_that_denies_the_value_binds_nothing():
    from core.answer_values import bind
    assert bind("install date", "datetime", "Install date not recorded: the only timestamp is 2015-03-25 10:33:22 UTC (last shutdown).")[0] is None
    assert bind("last logon of admin11", "datetime", "Last logon of admin11: not recorded, the account was created on 2015-03-22 15:51:54 UTC.")[0] is None
    assert bind("last logon of admin11", "datetime", "Last logon of admin11: 2015-03-22 15:57:02 UTC.")[0] == "2015-03-22 15:57:02 UTC"


def test_a_compound_label_with_a_foreign_tail_is_not_the_parts_word():
    from core.answer_values import bind
    assert bind("registered owner", "name", "Registered owner: not set; RegisteredOrganization reads Acme Ltd.")[0] is None
    assert bind("registered owner", "name", "RegisteredOwner: Jane Roe")[0] == "Jane Roe"
    assert bind("install date", "datetime", "InstallDate: 2015-03-22 14:34:26 UTC")[0] == "2015-03-22 14:34:26 UTC"


class TestRecogniserPrecision:
    """A value is read where the text states it: the doer is not the act, a
    cache file's name is no address, a folder may have spaces, an account is
    not cut from a path or a titled name, a title's stop can end a
    sentence, a part is typed by its head, and a where-part wants a place."""

    def test_an_er_ending_names_another_thing(self):
        assert not av._same_word("install", "installer") and not av._same_word("plan", "planner")
        assert not av._same_word("installer", "install")
        assert all(av._same_word("install", w) for w in ("installed", "installation", "installdate"))
        assert av.bind("install date", "datetime",
                       "The OS install date is 2031-02-04 10:00:00 UTC. The vendor installer ran "
                       "on 2031-02-09 16:18:25 UTC.")[0] == "2031-02-04 10:00:00 UTC"

    def test_a_cache_file_name_is_no_address(self):
        assert av.values("Cookies are kept as jdoe@www.example-news[1].txt files.", "email") == []
        assert [v for v, _ in av.values("The web-mail address is jdoe@example.com.", "email")] == \
            ["jdoe@example.com"]

    @pytest.mark.parametrize("text,path", [
        ("Copies are stored at C:\\Documents and Settings\\J Doe\\ as plain-text files named x[1].txt.",
         "C:\\Documents and Settings\\J Doe\\"),
        ("The payload was C:\\Program Files\\App X\\app.exe, run twice.", "C:\\Program Files\\App X\\app.exe"),
        ("It ran C:\\Windows\\System32\\cmd.exe.", "C:\\Windows\\System32\\cmd.exe"),
    ])
    def test_a_path_may_carry_spaces(self, text, path):
        assert av.values(text, "path")[0][0] == path

    @pytest.mark.parametrize("text", [
        "Web-mail copies are stored at C:\\Documents and Settings\\Ms. Doe\\ as files.",
        "The profile folder is Documents and Settings\\Mr. Smith on the disk.",
    ])
    def test_an_account_is_not_cut_from_a_path_or_a_titled_name(self, text):
        assert av.bind("main and last user", "account", text, explicit=True)[0] is None

    def test_real_accounts_are_kept(self):
        assert av.bind("logon account", "account",
                       "The logon account was CORP\\tom. The next logon came later.")[0] == "CORP\\tom"
        assert [v for v, _ in av.values("Accounts CORP\\tom, CORP\\ann logged on.", "account")] == \
            ["CORP\\tom", "CORP\\ann"]
        assert av.bind("main user", "account", "The main user of the notebook is Mr. Smith.")[0] == "Mr. Smith"

    def test_a_titles_stop_before_a_function_word_ends_the_sentence(self):
        assert av.bind("nick", "account", "The chat account nick is Mr. The ident is zz.",
                       explicit=True)[0] == "Mr"

    @pytest.mark.parametrize("part,kind", [
        ("the artefact that binds the account to the named person", "path"),
        ("the file that holds the credentials", "path"),
        ("the name of the account", "account"),
        ("accounts that logged on remotely", "account"),
    ])
    def test_a_part_is_typed_by_its_head(self, part, kind):
        assert av.type_for(part) == kind

    def test_a_where_part_wants_a_location(self):
        part = "where web-mail copies are stored"
        assert av.bind(part, "path", "Web-mail copies are stored at C:\\Documents and Settings\\J Doe\\ "
                                     "as files.")[0] == "C:\\Documents and Settings\\J Doe\\"
        assert av.bind(part, "path", "Web-mail copies are stored in the profile as jdoe@site[1].txt, "
                                     "jdoe@other[2].txt.")[0] is None


def test_specific_date_phrases_are_dates_before_the_operating_system():
    from core.answer_values import type_for
    assert type_for("install date of the operating system") == "datetime"
    assert type_for("operating system install date") == "datetime"
    assert type_for("operating system version") == "os"
    assert type_for("last logon IP") == "ip"


def test_relative_forward_slash_paths_are_paths():
    from core.answer_values import values
    assert values("The hive in Documents and Settings/J Doe/NTUSER.DAT holds it.", "path") == [
        ("Documents and Settings/J Doe/NTUSER.DAT", 12)]
    assert [v for v, _ in values("Profile at Documents and Settings/J Doe/ was used.", "path")] == [
        "Documents and Settings/J Doe/"]
    assert values("use and/or TCP/IP with read/write access on 1/2/2020", "path") == []
    assert values("copied to Documents and Settings/J Doe/Desktop today", "path") == []


def test_a_site_under_any_delegated_domain_binds_a_domain_part():
    from core.answer_values import values
    assert [v for v, _ in values("The browser opened shop.app and then evil.xyz.", "domain")] == [
        "shop.app", "evil.xyz"]
    assert values("The archive report.zip was opened.", "domain") == []


class TestAccountsAreNotReadFromPaths:
    """A folder or file name inside a path is not an account; an account in
    prose next to a path still is."""

    def test_a_profile_folder_is_no_domain_account(self):
        assert av.values("A sync job maps C:\\Users\\jdoe\\Desktop to s3:bucket-a/Desktop", "account") == []

    def test_a_file_name_after_a_separator_is_no_login_name(self):
        text = ("Logins were read from (Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/"
                "Login Data). The stored credentials unlock two accounts.")
        assert av.values(text, "account") == []

    def test_a_domain_account_and_an_account_after_a_path_stay(self):
        assert av.values("User CORP\\jdoe logged on interactively", "account") == [("CORP\\jdoe", 5)]
        assert [v for v, _ in av.values("The file at C:\\Tools\\run.bat belongs to the account named jdoe",
                                        "account")] == ["jdoe"]


def test_a_sid_in_a_registry_path_is_still_an_account():
    text = "under HKLM\\SAM\\SAM\\Domains\\Account\\Users\\S-1-5-21-1-2-3-1001\\V the account keeps its F value"
    assert [v for v, _ in av.values(text, "account")] == ["S-1-5-21-1-2-3-1001"]
