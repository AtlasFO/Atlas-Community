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
        text = "DC01 and DESKTOP-K4Q7Z2M and N-3B8RTW2PL6XQ9; claim C0009; CVE-2021-1234; T1059.001; bastion"
        got = {v for v, _ in av.values(text, "host", known_hosts=["Bastion"])}
        assert {"DC01", "DESKTOP-K4Q7Z2M", "N-3B8RTW2PL6XQ9", "bastion"} <= got
        assert not {"C0009", "CVE-2021", "T1059"} & got

    def test_accounts_in_their_written_forms(self):
        text = ("The only real user profile is 'Mr. Smith'; local account jsmith; CORP\\a.roe; "
                "S-1-5-21-1-2-3-1002; account creation by Administrator; John Roe (RID 1003)")
        got = {v for v, _ in av.values(text, "account")}
        # a bare lower-case word after "account" is prose unless the statement
        # writes it as a principal somewhere ("named X" does)
        assert {"Mr. Smith", "CORP\\a.roe", "S-1-5-21-1-2-3-1002", "Administrator", "John Roe"} <= got
        assert "jsmith" not in got
        assert "jsmith" in {v for v, _ in av.values("the local account named jsmith owns the laptop", "account")}
        assert "creation" not in got

    def test_dates_with_and_without_a_time_and_word_dates(self):
        text = "installed 2031-08-19; window 2031-03-27 to 2031-04-06; on 22 March 2031 and March 22, 2031 08:00; 22. März 2031"
        got = [v for v, _ in av.values(text, "datetime")]
        assert got[:3] == ["2031-08-19", "2031-03-27", "2031-04-06"]
        assert "22 March 2031" in got and "March 22, 2031" in got and "22. März 2031" in got

    def test_domains_and_urls_but_not_file_names(self):
        got = {v for v, _ in av.values("beacons to c2.example.com and http://evil.local/x; file example.exe; CORP01.LOCAL", "domain")}
        assert {"c2.example.com", "http://evil.local/x", "CORP01.LOCAL"} <= got
        assert "example.exe" not in got

    def test_macs_zones_os_and_identifiers(self):
        assert [v for v, _ in av.values("NIC MAC 00005e005301 (00:00:5E:00:53:01) build 6.3.9600.17031", "mac")] == ["00005e005301", "00:00:5E:00:53:01"]
        assert [v for v, _ in av.values("Eastern Standard Time, Bias 300, UTC-5", "zone")] == ["Eastern Standard Time", "Bias 300", "UTC-5"]
        assert av.values("runs Windows XP Professional SP1; Windows Server 2012 R2 (build 6.3.9600.17031)", "os")[0][0] == "Windows XP Professional SP1"
        got = {v for v, _ in av.values("USB#1 serial 7A210098760543212345, volume serial 1A2B-3C4D, {12345678-1234-1234-1234-123456789abc}", "identifier")}
        assert {"7A210098760543212345", "1A2B-3C4D", "{12345678-1234-1234-1234-123456789abc}"} <= got

    def test_a_count_is_the_number_beside_the_counted_noun(self):
        assert av.bind("how many accounts were created", "count",
                       "On 2031-03-22 the user created 3 new local accounts on CORP-WS01 (EID 4720).")[0] == "3"
        assert av.bind("how many accounts were created", "count",
                       "On 2031-03-22 accounts were reviewed; the record 4720 shows nothing.")[0] is None


class TestBinding:
    NET = "Network: delivery IP is 203.0.113.44 (external, attacker host 'attacker-vm'); C2 IP is 10.0.0.90 (internal)"
    NIC = "Network identity of the notebook during the scanner setup: IP address 10.0.0.111, NIC MAC 00005e005301 on the PCMCIA card"

    def test_each_part_takes_the_value_of_its_own_clause(self):
        assert av.bind("the delivery IP", "ip", self.NET)[0] == "203.0.113.44"
        assert av.bind("the C2 IP", "ip", self.NET)[0] == "10.0.0.90"

    def test_the_nearest_value_in_a_comma_joined_clause(self):
        assert av.bind("IP", "ip", self.NIC)[0] == "10.0.0.111"
        assert av.bind("MAC", "mac", self.NIC)[0] == "00005e005301"

    def test_a_part_without_a_qualifier_reads_the_first_sentence_only(self):
        st = ("Initial access to DC01 via RDP brute force from external IP 203.0.113.44 at 2031-03-01 04:12:30 UTC. "
              "Later at 2031-03-02 01:00 UTC more.")
        assert av.bind("with timestamp", "datetime", st)[0] == "2031-03-01 04:12:30 UTC"
        assert av.bind("operating system", "os", "The Acme NB7 notebook runs Windows XP (NTFS volume, offset sector 63).")[0] == "Windows XP"

    def test_a_value_of_the_right_kind_in_the_wrong_clause_does_not_answer(self):
        st = ("Device and system baseline: the seized evidence is an EnCase image of the notebook. "
              "Acquired 2031-09-20 10:00 UTC by the examiner.")
        assert av.bind("install date", "datetime", st) == (None, "")
        assert av.bind("install date", "datetime",
                       "Windows XP was installed on 2031-08-19 21:05:40 UTC (SOFTWARE InstallDate).")[0] == "2031-08-19 21:05:40 UTC"

    def test_qualifiers_match_by_stem_and_short_tokens_count(self):
        assert av.bind("computer name", "host", "The computer name is N-3B8RTW2PL6XQ9 and the primary domain is unknown.")[0] == "N-3B8RTW2PL6XQ9"
        assert av.bind("timezone", "zone", "The notebook's time zone is Pacific Standard Time (Bias 480).")[0] == "Pacific Standard Time"

    def test_non_value_kinds_bind_nothing(self):
        assert av.bind("whether it is recoverable", "yes_no", "Yes, the files are recoverable.") == (None, "")
        assert av.bind("prove the connection", "relation", "They match.") == (None, "")


class TestPrintedValuePrecision:
    """What the report prints as a part's value must be the value: whole
    file names, times with their zone, the machine's own name, and each
    sibling part's own value."""

    def test_file_names_with_spaces_are_taken_whole(self):
        text = ('The Desktop holds "The Short Note.docx" (816KB), "Plans.docx" and "Quarterly Plan '
                'Draft.pptx"; the menu at C:\\Share\\Team\\Family Menu.txt (512 bytes) and Desk_Notes.txt')
        got = [v for v, _ in av.values(text, "path")]
        assert got == ["The Short Note.docx", "Plans.docx", "Quarterly Plan Draft.pptx",
                       "C:\\Share\\Team\\Family Menu.txt", "Desk_Notes.txt"]
        unquoted = "The Desktop holds The Short Note.docx, Plans.docx, Quarterly Plan Draft.pptx and TRIP LIST.docx."
        assert [v for v, _ in av.values(unquoted, "path")] == [
            "The Short Note.docx", "Plans.docx", "Quarterly Plan Draft.pptx", "TRIP LIST.docx"]
        assert av.bind("the menu file", "path", "Data theft: the menu file C:\\Share\\Team\\Family Menu.txt was opened at 09:15 UTC.")[0] == "C:\\Share\\Team\\Family Menu.txt"

    def test_a_time_keeps_its_zone_and_utc_wins(self):
        text = "Lateral movement at 2031-03-01 05:27:44 DC01 time (~04:27 UTC, 1h VM clock skew); logon 2031-03-01 04:12:30 UTC"
        got = [v for v, _ in av.values(text, "datetime")]
        assert got[0] == "2031-03-01 04:12:30 UTC" and "2031-03-01 05:27:44 DC01 time" in got
        assert av.bind("when", "datetime", "The attacker moved to the desktop at 2031-03-01 05:27:44 DC01 time (~04:27 UTC).")[0] == "2031-03-01 05:27:44 DC01 time"

    def test_a_host_label_is_the_computer_name_only_when_named_so(self):
        assert av.bind("computer name", "host", "The Acme NB7 notebook runs Windows XP (NTFS volume).", known_hosts=["NB7"]) == (None, "")
        assert av.bind("computer name", "host", "The computer name of the NB7 notebook is N-3B8RTW2PL6XQ9.", known_hosts=["NB7"])[0] == "N-3B8RTW2PL6XQ9"
        assert av.values("host NB7 was imaged; computer name NB7", "host", known_hosts=["NB7"], name_part=True)[0][0] == "NB7"
        assert av.values("host NB7 was imaged", "host", known_hosts=["NB7"], name_part=True) == []

    def test_sibling_parts_keep_their_sub_kind_words(self):
        assert av.qualifier("SMTP address") == {"smtp"} and av.qualifier("web-mail address") == {"web-mail"}
        assert av.bind("web-mail address", "email", "The user's web-mail address is x7k2q9m4p1@webmail.example.com, from the web-mail cookie.")[0] == "x7k2q9m4p1@webmail.example.com"
        assert av.bind("web-mail address", "email", "SMTP email address jane.doe@mail.example.net, SMTP server smtp.mail.example.net.") == (None, "")
        assert av.bind("SMTP address", "email", "SMTP email address jane.doe@mail.example.net, SMTP server smtp.mail.example.net.")[0] == "jane.doe@mail.example.net"

    def test_a_shortcut_never_wins_over_the_file_it_points_to(self):
        st = ("Data theft on FILESRV01: the menu file at C:\\Share\\Team\\Family Menu.txt (512 bytes) was opened at "
              "09:15 UTC; a Recent Items shortcut (C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\Family Menu.lnk, "
              "MFT 9021) records the open.")
        assert av.bind("the menu file", "path", st)[0] == "C:\\Share\\Team\\Family Menu.txt"
        assert av.bind("the menu file", "path", st, explicit=True)[0] == "C:\\Share\\Team\\Family Menu.txt"
        assert av.bind("the file", "path", "Only the shortcut C:\\Users\\admin\\Recent\\Family Menu.lnk survives.")[0].endswith(".lnk")


def test_a_value_carrying_the_qualifier_word_wins_over_the_next_value_in_a_list():
    """A multi-word file name starts before the qualifier word it contains;
    ranked by its start alone it would lose to the next name in a comma
    list. The word is the value's own, so the value wins on both paths."""
    from core.answer_values import bind
    clause = ("Recent-items shortcuts on the workstation point at four documents "
              "on the share: Weekly Menu.txt, Desk_Notes.txt, Roadmap.txt, Budget.txt.")
    assert bind("the menu file", "path", clause)[0] == "Weekly Menu.txt"
    assert bind("the menu file", "path", clause, explicit=True)[0] == "Weekly Menu.txt"
    # a qualifier that names a later value still binds that value
    assert bind("the roadmap file", "path", clause)[0] == "Roadmap.txt"


def test_the_fuller_form_wins_when_both_forms_carry_the_qualifier_word():
    """A conclusion names a file twice, bare and as its full path; both carry
    the qualifier word, and the full path is the more useful answer."""
    from core.answer_values import bind
    clause = "Weekly Menu.txt (C:\\Share\\Team\\Weekly Menu.txt, 512 bytes, inode 4242) was opened at 09:15 UTC."
    assert bind("the menu file", "path", clause)[0] == "C:\\Share\\Team\\Weekly Menu.txt"
    assert bind("the menu file", "path", clause, explicit=True)[0] == "C:\\Share\\Team\\Weekly Menu.txt"


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
    assert bind("the menu file", "path", "The stolen file was C:\\Share\\Team\\Family Menu.txt.")[0] == \
        "C:\\Share\\Team\\Family Menu.txt"


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
    ("the plan documents", "path", "The folder holds Plans.docx, notes.txt and plan_final.pdf.", {"Plans.docx", "plan_final.pdf"}),
    ("the plan documents", "path", "The folder holds Plans.docx, meeting_notes_final_version.txt and plan_final.pdf.", {"Plans.docx", "plan_final.pdf"}),
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
    assert bind("install date", "datetime", "Install date not recorded: the only timestamp is 2031-03-25 11:41:37 UTC (last shutdown).")[0] is None
    assert bind("last logon of admin7", "datetime", "Last logon of admin7: not recorded, the account was created on 2031-03-22 16:02:11 UTC.")[0] is None
    assert bind("last logon of admin7", "datetime", "Last logon of admin7: 2031-03-22 16:08:45 UTC.")[0] == "2031-03-22 16:08:45 UTC"


def test_a_compound_label_with_a_foreign_tail_is_not_the_parts_word():
    from core.answer_values import bind
    assert bind("registered owner", "name", "Registered owner: not set; RegisteredOrganization reads Acme Ltd.")[0] is None
    assert bind("registered owner", "name", "RegisteredOwner: Jane Roe")[0] == "Jane Roe"
    assert bind("install date", "datetime", "InstallDate: 2031-03-22 13:20:05 UTC")[0] == "2031-03-22 13:20:05 UTC"


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


def test_a_code_span_path_binds_whole():
    text = "The dropper `C:\\Users\\jane.doe\\AppData\\evil.exe` ran on CORP-WS01."
    assert [v for v, _ in av.values(text, "path")][0] == "C:\\Users\\jane.doe\\AppData\\evil.exe"
    assert [v for v, _ in av.values("copied `C:\\Temp` by `CORP\\jdoe`", "path")] == ["C:\\Temp"]


def test_a_code_span_relative_path_binds_whole():
    got = [v for v, _ in av.values("carved into `exports/carved/x.bin` then", "path")]
    assert got[0] == "exports/carved/x.bin"


class TestABeliefNamedForAPartBindsOnlyWhatItSingles:
    """A belief the analyst named for a part binds the value beside the part's
    words, or the one value of the kind it states; with several and no clause
    saying which, it binds none and the refusal names them."""

    def test_a_host_inside_a_longer_host_name_is_no_host(self):
        assert av.values("CORP-WS01 was the attacker's host.", "host") == [("CORP-WS01", 0)]
        assert av.bind("the attacker's host", "host", "CORP-WS01 was the attacker's host.",
                       explicit=True)[0] == "CORP-WS01"

    def test_an_fqdn_takes_its_host_name_with_it(self):
        assert av.values("Beacons reached CORP-WS01.example.com at night.", "host") == [
            ("CORP-WS01.example.com", 16)]

    def test_two_hosts_and_no_role_word_bind_none_and_are_listed(self):
        st = "Logons from CORP-WS02 reached CORP-DC01 over SMB."
        assert av.bind("the attacker's host", "host", st, explicit=True, known_hosts=["CORP-DC01"]) == (None, "")
        assert av.explicit_candidates("the attacker's host", "host", st) == ["CORP-WS02", "CORP-DC01"]
        assert av.bind("the attacker's host", "host", st, explicit=True, prefer=["CORP-WS02"])[0] == "CORP-WS02"
        assert av.explicit_candidates("the attacker's host", "host", st, prefer=["CORP-WS02"]) == []

    def test_the_one_value_a_belief_states_binds(self):
        assert av.bind("the attacker's host", "host", "Logons from CORP-WS02 were seen over SMB.",
                       explicit=True)[0] == "CORP-WS02"

    def test_a_clause_with_the_parts_words_that_denies_the_value_binds_nothing(self):
        st = "Network: delivery IP is 203.0.113.7; the C2 IP could not be established."
        assert av.bind("the C2 IP", "ip", st, explicit=True) == (None, "")
        assert av.bind("the delivery IP", "ip", st, explicit=True)[0] == "203.0.113.7"
        assert av.bind("the C2 IP", "ip", "Network: the C2 IP is unknown; delivery from 203.0.113.7.",
                       explicit=True) == (None, "")

    def test_a_negator_about_something_else_does_not_stop_the_bind(self):
        st = "The attacker's host was not a domain member. It was CORP-WS02."
        assert av.bind("the attacker's host", "host", st, explicit=True)[0] == "CORP-WS02"

    def test_a_file_over_its_shortcut_and_utc_over_local_time_count_as_one(self):
        st = ("The recent-files list shows C:\\Users\\jane.doe\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
              "plan.docx.lnk for C:\\Share\\plan.docx.")
        assert av.bind("the staged document", "path", st, explicit=True)[0] == "C:\\Share\\plan.docx"
        st = "jane.doe signed in at 2031-03-04 10:00:00 UTC (2031-03-04 11:00:00 local)."
        assert av.bind("the first logon time", "datetime", st, explicit=True)[0] == "2031-03-04 10:00:00 UTC"

    def test_a_typed_principal_matches_either_half_of_name_and_sid(self):
        st = "The file was created by jane.doe (S-1-5-21-1111111111-2222222222-3333333333-1104)."
        got = av.bind("the account that created the file", "account", st, explicit=True,
                      prefer=["S-1-5-21-1111111111-2222222222-3333333333-1104"])
        assert got[0] == "jane.doe (S-1-5-21-1111111111-2222222222-3333333333-1104)"


class TestAFileClassNamedByThePart:
    LOG_AND_EXE = "The analyst found C:\\Temp\\example3.log and C:\\Temp\\tool.exe."

    def test_the_class_comes_from_the_parts_head_noun(self):
        assert av.file_class_named("an executable") == "executable"
        assert av.file_class_named("the log of the executable") == "log"
        assert av.file_class_named("which files were executed") == ""

    def test_an_executable_binds_the_executable_named_or_linked(self):
        assert av.bind("an executable", "path", self.LOG_AND_EXE, explicit=True)[0] == "C:\\Temp\\tool.exe"
        # The class word is checked on the value, so a linked belief needs
        # no word "executable" in its first sentence.
        assert av.bind("an executable", "path", self.LOG_AND_EXE)[0] == "C:\\Temp\\tool.exe"

    def test_a_file_of_no_class_stays_and_one_of_another_class_never_binds(self):
        assert av.bind("an executable", "path", "The dropper /usr/local/bin/tool ran at boot.")[0] == \
            "/usr/local/bin/tool"
        assert av.bind("an executable", "path", "Only C:\\Temp\\example3.log was written.") == (None, "")

    def test_a_value_of_the_class_is_preferred_and_no_other_value_is_lost(self):
        # A value of the named class wins over one of no class in the same
        # text; alone, a staging or masquerading name still answers.
        st = "The FTP session to 203.0.113.9 carried photo1.jpg and tool.exe."
        assert av.bind("an executable", "path", st)[0] == "tool.exe"
        assert av.bind("an executable", "path", st, explicit=True)[0] == "tool.exe"
        assert av.bind("an executable", "path", "It dropped C:\\Users\\jane.doe\\AppData\\Local\\Temp\\update.tmp.",
                       explicit=True)[0].endswith("update.tmp")
        assert av.bind("an executable", "path", "The loader ran holiday.jpg from the share.")[0] == "holiday.jpg"
        assert av.bind("the binary", "path", "It wrote /tmp/payload.bin and ran it.")[0] == "/tmp/payload.bin"

    def test_the_class_is_preferred_across_clauses_when_the_belief_is_named_for_the_part(self):
        # The value of the class sits in a later clause; a belief the analyst
        # named for the part (explicit) must still answer with it, as a
        # linked belief already did, never with the first clause's picture.
        st = ("jane.doe's account stored pic1.jpg, pic3.jpg and notes.zip on CORP-WS01; "
              "tool.exe and the pictures were requested from the web directory.")
        assert av.bind("an executable", "path", st, explicit=True)[0] == "tool.exe"
        assert av.bind("an executable", "path", st)[0] == "tool.exe"
        # Alone, a no-class name in the first clause still answers.
        assert av.bind("an executable", "path", "It stored stage.tmp; pic1.jpg was requested later.",
                       explicit=True)[0] == "stage.tmp"

class TestWordsMatchByTheirStems:
    @pytest.mark.parametrize("a, b", [("key", "keys"), ("log", "logs"), ("wiping", "wiped"),
                                      ("copied", "copies"), ("deleting", "deleted"),
                                      ("encrypted", "encryption"), ("exfiltration", "exfiltrated"),
                                      ("authentication", "authenticated"), ("creation", "created")])
    def test_inflections_of_one_word_match(self, a, b):
        assert av._same_word(a, b) and av._same_word(b, a)

    @pytest.mark.parametrize("a, b", [("same", "sam"), ("note", "not"), ("hat", "hate"),
                                      ("installer", "install"), ("ration", "rated"), ("early", "ears")])
    def test_short_look_alikes_and_agent_nouns_do_not(self, a, b):
        assert not av._same_word(a, b) and not av._same_word(b, a)


class TestANameAndItsSidAreOnePrincipal:
    SID = "S-1-5-21-1111111111-2222222222-3333333333-1104"

    @pytest.mark.parametrize("text, want", [
        (f"The file was created by jane.doe ({SID}).", f"jane.doe ({SID})"),
        (f"{SID} (jane.doe) logged on.", f"jane.doe ({SID})"),
        (f"EXAMPLE\\jane.doe ({SID}) logged on.", f"EXAMPLE\\jane.doe ({SID})"),
        ("Administrator (S-1-5-21-1111111111-2222222222-3333333333-500) logged on.",
         "Administrator (S-1-5-21-1111111111-2222222222-3333333333-500)"),
        (f"The file was created by Jane Doe ({SID}).", f"Jane Doe ({SID})"),
        ("Logon by The Administrator (S-1-5-21-1111111111-2222222222-3333333333-500).",
         "Administrator (S-1-5-21-1111111111-2222222222-3333333333-500)"),
    ])
    def test_name_and_sid_in_apposition_read_as_one(self, text, want):
        assert [v for v, _ in av.values(text, "account")] == [want]

    @pytest.mark.parametrize("text", [
        f"the account ({SID}) logged on.",
        f"{SID} (the local administrator) logged on.",
    ])
    def test_a_generic_word_beside_the_sid_is_no_name(self, text):
        assert [v for v, _ in av.values(text, "account")] == [self.SID]
