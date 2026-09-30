"""Exit-code conventions see through wrappers, and artifact tokens do not
mistake a credential pair for a path."""
from core.entities import artifact_tokens
from core.executor import _apply_exit_conventions, _cmd_verb


def test_verb_is_the_program_behind_its_wrappers():
    assert _cmd_verb(["sudo", "ngrep", "-q", "-I", "x.pcap"]) == "ngrep"
    assert _cmd_verb("sudo -n /usr/bin/tcpdump -r x.pcap") == "tcpdump"
    assert _cmd_verb(["sudo", "-u", "tcpdump", "tcpdump", "-r", "x"]) == "tcpdump"
    assert _cmd_verb(["timeout", "300", "zeek", "-r", "x"]) == "zeek"
    assert _cmd_verb(["env", "LC_ALL=C", "strings", "x"]) == "strings"
    assert _cmd_verb(["nice", "-n", "10", "foremost"]) == "foremost"
    assert _cmd_verb(["ngrep"]) == "ngrep"
    assert _cmd_verb("") == ""


def test_grep_family_exit_one_is_a_no_match_answer_even_under_sudo():
    result = {"success": False, "exit_code": 1, "stderr": "",
              "stdout": "input: x.pcap\nmatch (JIT): telnet\n",
              "cmd": "sudo ngrep -q -I x.pcap -i telnet tcp"}
    _apply_exit_conventions(result)
    assert result["success"] is True and result["no_match"] is True
    assert result["stdout"].startswith("input: x.pcap")

    silent = {"success": False, "exit_code": 1, "stderr": "", "stdout": "",
              "cmd": ["grep", "-c", "needle", "hay.txt"]}
    _apply_exit_conventions(silent)
    assert silent["success"] is True and silent["stdout"] == "grep: no match"


def test_a_real_error_on_exit_one_stays_a_failure():
    result = {"success": False, "exit_code": 1, "stdout": "",
              "stderr": "ngrep: cannot open x.pcap", "cmd": "sudo ngrep -I x.pcap a"}
    _apply_exit_conventions(result)
    assert result["success"] is False


def test_silent_mmls_answer_still_applies_under_sudo():
    result = {"success": False, "exit_code": 1, "stdout": "", "stderr": "",
              "cmd": "sudo mmls /evidence/disk.dd"}
    _apply_exit_conventions(result)
    assert result["success"] is True and "partition table" in result["stdout"]


def test_credential_pair_is_not_an_artifact_path():
    assert artifact_tokens("FTP credentials gnome/gnome123 used on the server") == set()


def test_a_slash_separated_list_of_words_is_not_a_path():
    """"System/lsass/svchost created 01:22" names processes, not files; a
    path of three segments needs something path-shaped in it."""
    assert artifact_tokens("System/lsass/svchost created 2020-09-19T01:22") == set()
    assert artifact_tokens("permissions read/write/execute on the share") == set()
    assert artifact_tokens("ports 215/38088/38090 open on the host") == set()
    # Anchored, numbered or file-ending runs are still paths.
    assert {"ws01", "config"} <= artifact_tokens("hive WS01/config/SYSTEM copied")
    assert "notes.txt" in artifact_tokens("kept at staging/2020/notes.txt")
    assert {"carved", "x.bin"} <= artifact_tokens("carved to exports/carved/x.bin")


def test_a_quoted_url_and_a_bare_extension_are_not_artifacts():
    """A disposition that quotes XML namespace URLs and names ".docx/.pptx"
    files described nothing a call could have read; the lineage gate
    refused it for six artifacts that were the URL's path segments and two
    bare extensions."""
    text = ("Recurring URLs http://www.w3.org/tr/rec-html40 and "
            "http://schemas.microsoft.com/office/2004/12/omml are XML namespace "
            "identifiers embedded in Office .docx/.pptx files, not exfiltration "
            "channels.")
    assert artifact_tokens(text) == set()
    # Real files next to a URL are still seen.
    assert "report.docx" in artifact_tokens(
        "exports/carved/report.docx cites http://schemas.microsoft.com/office/2004/12/omml")


def test_a_mail_store_is_an_artifact_a_finding_and_a_listing_can_share():
    """The lineage gate compares a finding's artifact names with those the
    cited call printed; a store the extractor did not know as a file left
    a finding with nothing but the fragments of a spaced Windows path, and
    a listing that printed every store was refused as unrelated to it."""
    finding = ("Newsgroup subscriptions under Local Settings\\Application Data"
               "\\Microsoft\\Outlook Express\\{GUID}: alt.2600.dbx, "
               "alt.binaries.hacking.beginner.dbx; contacts in user.wab")
    listing = ("r/r 11443-128-4:\talt.2600.dbx\nr/r 11444-128-4:\t"
               "alt.binaries.hacking.beginner.dbx\nr/r 11460-128-3:\tFolders.dbx")
    shared = artifact_tokens(finding) & artifact_tokens(listing)
    # A multi-dot name is kept whole on both sides (the last label is the
    # extension); what must hold is that the two texts share the store.
    assert "alt.binaries.hacking.beginner.dbx" in shared
    assert shared - {"data", "outlook"}
    assert "user.wab" in artifact_tokens(finding)
    assert "gnome123" not in artifact_tokens("login gnome/gnome123 seen in rhino.log")


def test_real_relative_paths_still_count():
    assert {"carved", "x.bin"} <= artifact_tokens("carved to exports/carved/x.bin")
    assert "rhino.log" in artifact_tokens("packets in evidence/rhino.log")
    assert {"config", "system"} <= artifact_tokens("hive Windows/System32/config/SYSTEM")
    assert "notes.txt" in artifact_tokens("see docs/notes.txt for details")


def test_protocol_and_dot_rendered_fragments_are_not_artifact_paths():
    # Quoted request lines and dot-rendered binary make slash pairs whose
    # tail is not a file name; treating them as artifacts made a finding
    # about traffic name things no call could have read.
    toks = artifact_tokens(
        "GET /images/photo1.jpg HTTP/1.1..Accept: */*..User-Agent: Mozilla/4.0")
    assert "http" not in toks and "mozilla" not in toks
    assert not any(".." in t or t in ("1.1", "4.0") for t in toks)
    assert "photo1.jpg" in toks


def test_relative_scan_never_starts_inside_a_hyphenated_name():
    toks = artifact_tokens(
        "tcpdump -r /srv/cases/ACME-INC-r7/analysis/pcap_staging/x2_ab12cd34.pcap")
    assert "acme-inc-r7" in toks and "x2_ab12cd34.pcap" in toks
    assert "inc-r7" not in toks


def test_windows_profile_directories_are_places_not_artifacts():
    """"Application Data\\Microsoft\\Outlook Express" says where in the
    profile a store sits; a finding about it is not about "microsoft" or
    "data", and a call that read the store is not unrelated for lacking
    those words."""
    toks = artifact_tokens(
        r"24 .dbx files in C:\Documents and Settings\Mr. Evil\Local Settings\Application Data"
        r"\Identities\{3D}\Microsoft\Outlook Express\alt.2600.dbx")
    for place in ("documents and settings", "local settings", "application data",
                  "identities", "microsoft", "data", "settings"):
        assert place not in toks, place
    assert "alt.2600.dbx" in toks and "mr. evil" in toks and "outlook express" in toks


def test_a_windows_path_with_spaces_is_one_path_and_prose_after_it_is_not():
    from core.entities import extract
    ents = extract(r"ClamAV flagged C:\Program Files\Cain\Abel.dll (inode 9958). Abel is part of Cain")
    assert "path:c:/program files/cain/abel.dll" in ents
    assert "file:abel.dll" in ents
    assert not any(e.startswith("path:") and "inode" in e for e in ents)
    toks = artifact_tokens(r"copied to C:\Users\bob and later D:\backup\x.zip")
    assert {"bob", "backup", "x.zip"} <= toks and "and later" not in toks
