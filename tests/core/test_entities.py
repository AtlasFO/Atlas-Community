"""Tests for core/entities.py — canonical forensic entity extraction."""
import pytest

from core.entities import DISCRIMINATIVE_TYPES, discriminative, extract


class TestExtractionBasics:
    def test_ipv4_canonical_strips_port_and_leading_zeros(self):
        assert "ip:10.0.12.128" in extract("beacon to 10.0.12.128:443")
        assert "ip:10.0.12.128" in extract("connects to 10.000.012.128")

    def test_invalid_ipv4_octet_rejected(self):
        assert not any(e.startswith("ip:") for e in extract("version 999.1.2.3"))

    def test_ipv6_compresses(self):
        a = extract("C2 at 2001:0db8:0000:0000:0000:0000:0000:0001")
        b = extract("C2 at 2001:db8::1")
        assert "ip:2001:db8::1" in a
        assert a & b

    def test_hashes_typed_by_length_and_casefolded(self):
        md5 = "0C0DE5A3B1C2D4E6F708192A3B4C5D6E"
        sha1 = "a" * 40
        sha256 = "B" * 64
        ents = extract(f"hashes {md5} {sha1} {sha256}")
        assert f"md5:{md5.lower()}" in ents
        assert f"sha1:{sha1}" in ents
        assert f"sha256:{'b' * 64}" in ents

    def test_windows_path_canonicalizes_separators_and_case(self):
        ents = extract(r"dropped C:\Windows\Temp\TOOLX.exe on the host")
        assert "path:c:/windows/temp/toolx.exe" in ents
        assert "file:toolx.exe" in ents

    def test_unc_path_yields_host_entity(self):
        ents = extract(r"staged to \\10.0.12.128\share\out.zip")
        assert "host:10.0.12.128" in ents
        assert "file:out.zip" in ents

    def test_unix_path(self):
        ents = extract("webshell at /var/www/html/shell.php found")
        assert "path:/var/www/html/shell.php" in ents
        assert "file:shell.php" in ents

    def test_registry_key(self):
        ents = extract(r"persistence via HKLM\Software\Microsoft\Windows\CurrentVersion\Run")
        assert any(e.startswith("reg:hklm/software/") for e in ents)

    def test_email_and_url(self):
        ents = extract("mail from jane.doe@EXAMPLE.org see http://Evil.example/p.php.")
        assert "email:jane.doe@example.org" in ents
        assert "url:http://evil.example/p.php" in ents

    def test_cve_and_mitre_case_insensitive(self):
        ents = extract("exploited cve-2031-0001 mapped to T1059.001")
        assert "cve:CVE-2031-0001" in ents
        assert "technique:T1059.001" in ents

    def test_mitre_id_not_double_extracted_as_filename(self):
        ents = extract("technique T1059.001 observed")
        assert "file:t1059.001" not in ents

    def test_timestamp_minute_resolution_utc(self):
        a = extract("logon at 2023-01-24T09:15:00Z")
        b = extract("event 2023-01-24 09:15:42")
        assert "ts:2023-01-24T09:15" in a
        assert a & b  # second-level skew still matches at minute resolution

    def test_timestamp_offset_normalized_to_utc(self):
        ents = extract("at 2023-01-24T10:15:00+01:00")
        assert "ts:2023-01-24T09:15" in ents

    def test_flag_token(self):
        ents = extract("recovered flag{example-f1ag-0c0de} from console")
        assert "flag:flag{example-f1ag-0c0de}" in ents

    def test_account_two_components_only(self):
        ents = extract(r"logon by CORP\jdoe succeeded")
        assert "account:corp/jdoe" in ents
        # trailing backslash means path fragment, not account
        ents2 = extract(r"under Windows\Temp\payload.exe")
        assert not any(e.startswith("account:") for e in ents2)

    def test_version_number_is_not_a_filename(self):
        assert not any(e.startswith("file:") for e in extract("upgraded to 3.14 today"))

    def test_empty_and_plain_prose(self):
        assert extract("") == set()
        assert extract("the attacker moved laterally between hosts") == set()


class TestDiscriminative:
    def test_generic_types_excluded(self):
        ents = {"technique:T1059", "cve:CVE-2024-1", "path:c:/windows",
                "md5:" + "a" * 32, "ip:1.2.3.4"}
        d = discriminative(ents)
        assert "md5:" + "a" * 32 in d
        assert "ip:1.2.3.4" in d
        assert "technique:T1059" not in d
        assert "cve:CVE-2024-1" not in d
        assert "path:c:/windows" not in d

    def test_types_frozen(self):
        assert "sha256" in DISCRIMINATIVE_TYPES
        assert "technique" not in DISCRIMINATIVE_TYPES


def test_images_media_and_captures_are_files():
    ents = extract("recovered gorilla.jpg and session.pcap from the drive")
    assert {"file:gorilla.jpg", "file:session.pcap"} <= ents


class TestReadingATraceExcerpt:
    """A structured result reaches the trace as JSON, so what a scan sees is
    an encoded newline, not a newline. Decoding is the inverse of how it was
    written, which is what makes it safe on a Windows path."""

    def test_an_encoded_newline_becomes_a_line_break(self):
        import json
        from core.entities import scan_text
        raw = json.dumps({"listing": "one.bmp\n-rwx------ 1 owner group"})
        assert "\\n" in raw                     # encoded, not a line break
        out = scan_text(raw)
        assert "\\n" not in out
        assert "one.bmp" in out and "-rwx------" in out

    def test_a_windows_path_survives_whole(self):
        import json
        from core.entities import scan_text
        raw = json.dumps({"path": r"C:\notes.txt", "user": r"CORP\jsmith"})
        out = scan_text(raw)
        assert r"C:\notes.txt" in out
        ents = extract(out)
        assert "account:corp/jsmith" in ents
        assert "file:notes.txt" in ents

    def test_text_that_is_not_json_is_untouched(self):
        from core.entities import scan_text
        for raw in ("the file one.bmp was carved", r"C:\Users\bob", "", "{"):
            assert scan_text(raw) == raw

    def test_a_bare_json_scalar_is_left_alone(self):
        from core.entities import scan_text
        assert scan_text('"just a string"') == '"just a string"'

    def test_a_cut_escaped_excerpt_gives_no_false_account(self):
        """An excerpt is kept only up to a cap, so it usually arrives cut
        mid-string and never parses. Two encoded line breaks around a file
        format's magic string must not read as one name with a separator in
        it, an account no evidence ever named: neither raw (the pair follows
        the escape's backslash) nor decoded (scan_text). Decoding itself is
        pinned by the other scan_text tests."""
        from core.entities import scan_text
        cut = '{"stdout": "binary blob \\njfif\\nphotoshop 3.0 \\nsome'
        # The pair follows a backslash (the escape's), so the account
        # pattern's separator lookbehind refuses it even undecoded.
        assert not [e for e in extract(cut) if e.startswith("account:")]
        assert not [e for e in extract(scan_text(cut))
                    if e.startswith("account:")]
        # Before a capitalised word the escape is read as one without decoding.
        assert not [e for e in extract('"\\nJFIF\\nPhotoshop 3.0"')
                    if e.startswith("account:")]

    def test_a_cut_excerpt_keeps_windows_paths_and_real_accounts(self):
        from core.entities import scan_text
        cut = ('{"path": "C:\\\\notes.txt", "u": "CORP\\\\jsmith", '
               '"cut": "abc')
        ents = extract(scan_text(cut))
        assert "account:corp/jsmith" in ents
        assert "file:notes.txt" in ents


class TestFormatNamespaceUrls:
    """A URL a namespace authority publishes as a document-format identifier
    is in every document of that format. The list is exact hosts only, a
    query never belongs to a namespace, a fragment may only be a bare term,
    and an authority that is not a plain host name fails closed: an
    indicator suppressed by mistake is lost silently."""

    EXCLUDED = (
        "http://schemas.microsoft.com/office/2004/12/omml",
        "http://www.w3.org/1999/xhtml",
        "http://www.w3.org/tr/rec-html40",
        "HTTP://SCHEMAS.MICROSOFT.COM/OFFICE/2004/12/OMML",
        "https://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha256",
        "http://purl.org/dc/elements/1.1/",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "https://ns.adobe.com/xap/1.0/",
        "schemas.openxmlformats.org",
        "ns.adobe.com",
        "schemas.microsoft.com.",
    )
    INDICATORS = (
        "schemas.attacker.example",
        "http://schemas.attacker.example/x",
        "ns.evil.example",
        "xsd.c2.example",
        "https://c2.example/ns/beacon",
        "https://attacker.example/evil.dtd",
        "https://attacker.example/x.xsd",
        "https://api.example.com/graphql/schema",
        "https://example.com/xml/ns/config",
        "https://example.com/config/settings.xsd",
        "http://w3.org.attacker.example/x",
        "http://evilw3.org/x",
        "http://purl.org/anything/else",
        "http://c2.evil.example\\@schemas.microsoft.com/payload",
        "http://user@schemas.microsoft.com/office",
        "http://schemas.microsoft.com:8080/office",
        "http://schemas.microsoft.com%2ex/office",
        "https://lists.w3.org/archives/public/www-archive/2026sep/att-0001/payload.bin",
        "http://validator.w3.org/nu/?doc=https://c2.evil.example/?d=secret",
        "http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http://c2.evil.example/x.xsl",
        "https://www.w3.org/wiki/Main_Page",
        "https://www.w3.org/2005/x.html#https://c2.evil.example/p",
        "http://schemas.micr\u043esoft.com/office/2004/12/omml",
        "http://schemas.microsoft.com../x",
        "https://www.w3.org/2000/../wiki/Main_Page",
        "https://www.w3.org/2000/%2e%2e/wiki/Main_Page",
        "ftp://schemas.microsoft.com/office",
        "http://203.0.113.9/update.php",
        "https://signin.aws.amazon.com/oauth?client_id=x",
        "https://drive.google.com/uc?id=abc",
        "http://cdn.example/schema.png",
        "https://c2.example/api/v1/beacon",
        "", "not a url",
    )

    def test_listed_authorities_are_excluded(self):
        from core.entities import is_format_namespace_url
        for url in self.EXCLUDED:
            assert is_format_namespace_url(url), url

    def test_everything_else_remains_an_indicator(self):
        from core.entities import is_format_namespace_url
        for url in self.INDICATORS:
            assert not is_format_namespace_url(url), url

    def test_a_schema_path_on_any_other_host_is_an_indicator(self):
        """A .xsd or .dtd on an arbitrary host is what an external-entity
        exfiltration looks like; a namespace-shaped path on an arbitrary
        host is an attacker's choice of path. Neither is format knowledge."""
        from core.entities import is_format_namespace_url
        assert not is_format_namespace_url("https://example.com/xml/ns/config")
        assert not is_format_namespace_url("https://example.com/config/settings.xsd")


def test_a_time_range_is_not_read_as_an_offset():
    from core.entities import extract
    assert {e for e in extract("FTP session 2031-04-26 21:10-21:15 from the host") if e.startswith("ts:")} == {"ts:2031-04-26T21:10"}
    assert "ts:2031-04-27T02:10" in extract("logged at 2031-04-26T21:10:00-05:00")
    assert "ts:2031-04-26T20:10" in extract("logged at 2031-04-26 21:10+0100")


def test_one_extension_list_and_domains_on_request():
    from core import entities as ent
    from core.ioc_catalog import _KNOWN_FILE_EXT
    assert _KNOWN_FILE_EXT is ent.FILE_EXTENSIONS and "com" not in ent.FILE_EXTENSIONS
    assert ent.extract("see readme.md and main.go") == {"file:readme.md", "file:main.go"}
    assert ent.extract("The user visited example.com daily.") == set()
    text = ("Beacons to evil.xyz and cdn.example.co.uk; report.zip, v1.2.3, a.roe, "
            "jane.doe@mail.example.org and https://x.example.net/a stay out.")
    assert ent.domains_in(text) == {"evil.xyz", "cdn.example.co.uk"}


def test_a_dotted_stem_keeps_its_last_label_as_the_extension():
    from core.entities import extract
    assert extract("setupapi.dev.log was read") == {"file:setupapi.dev.log"}
    assert extract("file.tar.gz, v1.2.3 and a.roe") == {"file:file.tar.gz"}


class TestDelimitersAroundAPath:
    """Prose wraps a path in a code span, quotes or brackets; the delimiter
    is not part of the path, and the file name stays an entity."""

    def test_a_code_span_path_keeps_its_file(self):
        ents = extract("The dropper `C:\\Users\\jane.doe\\AppData\\evil.exe` ran on CORP-WS01.")
        assert {"path:c:/users/jane.doe/appdata/evil.exe", "file:evil.exe"} <= ents

    def test_unc_registry_and_url_in_code_spans(self):
        assert {"path://corp-fs01/share/tool.exe", "file:tool.exe"} <= extract(
            "Copied `\\\\CORP-FS01\\share\\tool.exe` at noon.")
        assert "reg:hklm/software/run" in extract("Key `HKLM\\Software\\Run` was set.")
        assert "url:https://example.com/a/b.zip" in extract("Fetched `https://example.com/a/b.zip` then.")
        assert "url:http://evil.example/p.php" in extract("Visited http://evil.example/p.php\u201d once.")

    def test_brackets_and_quotes_nest(self):
        for text in ("Ran (C:\\Temp\\b.exe) once.", "(see C:\\Temp\\b.exe.)",
                     "(\u201cC:\\Temp\\b.exe\u201d)", "[C:\\Temp\\b.exe]"):
            assert {"path:c:/temp/b.exe", "file:b.exe"} <= extract(text), text

    def test_brackets_the_path_opened_stay(self):
        assert "path:c:/program files (x86)/app.exe" in extract("(C:\\Program Files (x86)\\app.exe)")
        assert "path:c:/temp/report(1).pdf" in extract("Saved C:\\Temp\\report(1).pdf there.")
        assert "reg:hklm/software/classes/clsid/{0000-1111}" in extract(
            "Key HKLM\\Software\\Classes\\CLSID\\{0000-1111} set.")

    def test_a_segment_stops_at_a_code_span(self):
        ents = extract("copied `C:\\Temp` by `CORP\\jdoe` at noon")
        assert {"path:c:/temp", "account:corp/jdoe"} <= ents

    def test_artifact_tokens_name_the_bare_file(self):
        from core.entities import artifact_tokens
        assert "b.exe" in artifact_tokens("Ran (C:\\Temp\\b.exe) once.")


def test_an_early_hour_range_is_not_read_as_a_negative_offset():
    """A negative offset counts only after seconds: "10:16-10:48" is a range
    whose second half would otherwise pass as the offset -10:48."""
    from core.entities import extract
    times = {e for e in extract("ran 2031-03-04 10:16-10:48 UTC on CORP-WS01") if e.startswith("ts:")}
    assert times == {"ts:2031-03-04T10:16"}
    assert {e for e in extract("logged 2031-03-04T10:16:00-05:00") if e.startswith("ts:")} == {"ts:2031-03-04T15:16"}
    assert {e for e in extract("logged 2031-03-04 10:16+02:00") if e.startswith("ts:")} == {"ts:2031-03-04T08:16"}
    assert {e for e in extract("logged 2031-03-04T10:16Z") if e.startswith("ts:")} == {"ts:2031-03-04T10:16"}
    # A seconds range: an offset is never followed by ":" or a digit.
    assert {e for e in extract("ran 2031-03-04 10:16:00-10:48:00 UTC") if e.startswith("ts:")} == {"ts:2031-03-04T10:16"}
    assert {e for e in extract("logged 2031-03-04T10:16:00-0500 on CORP-WS01") if e.startswith("ts:")} == {"ts:2031-03-04T15:16"}


class TestAPathFollowedByProse:
    """A spaced segment ends before a file-name-shaped token that whitespace
    follows, so the prose after a path keeps its own entities."""

    def test_the_file_and_the_account_behind_it_survive(self):
        ents = extract("C:\\Users\\jane.doe\\Downloads\\dropper.exe was run by CORP\\jane.doe")
        assert "path:c:/users/jane.doe/downloads/dropper.exe" in ents
        assert "file:dropper.exe" in ents
        assert "account:corp/jane.doe" in ents
        assert not any(" " in e for e in ents)

    def test_a_registry_key_behind_a_path_is_its_own_entity(self):
        ents = extract("C:\\Temp\\x.exe set HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        assert "path:c:/temp/x.exe" in ents
        assert "reg:hklm/software/microsoft/windows/currentversion/run" in ents

    def test_a_unc_path_followed_by_prose(self):
        ents = extract("\\\\CORP-DC01\\share\\notes.txt was copied by CORP\\jane.doe")
        assert "path://corp-dc01/share/notes.txt" in ents
        assert "host:corp-dc01" in ents
        assert "account:corp/jane.doe" in ents

    def test_spaced_system_directories_stay_segments(self):
        ents = extract("C:\\Documents and Settings\\jane.doe\\Local Settings\\Temp\\dropper.exe was run")
        assert "path:c:/documents and settings/jane.doe/local settings/temp/dropper.exe" in ents
        ents = extract("C:\\Program Files (x86)\\Vendor Tool\\tool.exe started")
        assert "path:c:/program files (x86)/vendor tool/tool.exe" in ents

    def test_a_dotted_directory_name_without_a_known_extension_stays_a_segment(self):
        ents = extract("C:\\Program Files (x86)\\Vendor ASP.NET\\ASP.NET Web Pages\\v1.0\\x.dll loaded")
        assert "path:c:/program files (x86)/vendor asp.net/asp.net web pages/v1.0/x.dll" in ents
        assert "file:asp.net" not in ents
        ents = extract("C:\\Data\\Build v1.2 files\\x.dll loaded")
        assert "path:c:/data/build v1.2 files/x.dll" in ents

    def test_a_known_extension_ends_the_segment_case_insensitively(self):
        ents = extract("C:\\Users\\jane.doe\\Downloads\\DROPPER.EXE was run by CORP\\jane.doe")
        assert "path:c:/users/jane.doe/downloads/dropper.exe" in ents
        assert "account:corp/jane.doe" in ents

    def test_ceiling_a_directory_named_like_a_file_before_a_space(self):
        """The remaining ceiling: a directory whose name holds a token ending
        in a known extension before a space is read as the path's end."""
        ents = extract("C:\\Program Files\\vendor\\Tool.js Kit\\x.dll loaded")
        assert "path:c:/program files/vendor/tool.js" in ents

    def test_a_registry_key_with_a_spaced_dotted_segment(self):
        ents = extract("HKLM\\SOFTWARE\\Vendor\\Uninstall\\Tool v2.1 x64\\DisplayName was set")
        assert "reg:hklm/software/vendor/uninstall/tool v2.1 x64/displayname" in ents
        assert not any(e.startswith("account:") for e in ents)

    def test_a_registry_key_ends_before_a_file_named_in_its_prose(self):
        ents = extract("HKCU\\Software\\Vendor\\Run Keys\\Updater set by x.exe for CORP\\jane.doe")
        assert "reg:hkcu/software/vendor/run keys/updater" in ents
        assert {"file:x.exe", "account:corp/jane.doe"} <= ents


# ── the names comparison (names_in, NamePool, unstated) ─────────────────
#
# One restatement check for the answer composer's sentence check and the
# conclusion door's basis rule: does a sentence restate only names its
# cited texts (and the question) state? Invented beliefs: a run of a tool
# on CORP-WS01, an archive on FILESRV, logons on CORP-WS02.

_BELIEFS = {
    "C0001": ("On 2031-03-02 10:15:22 UTC, jane.doe ran tool.exe on CORP-WS01 from "
              "C:\\\\Users\\\\jane.doe\\\\AppData\\\\Local\\\\Temp\\\\tool.exe (48,512 bytes).\nCORP-WS01\n"
              "Prefetch TOOL.EXE-1A2B3C4D.pf run count 3; downloaded from http://203.0.113.7/a/tool.exe "
              "at 10:11-10:14 UTC"),
    "C0002": ("An archive staged.7z was written to \\\\FILESRV\\share\\staged.7z by svc-backup; "
              "hosts CORP-WS01, CORP-WS02 and FILESRV connected.\nFILESRV"),
    "C0003": "Logons by jane.doe at 23:10 UTC and again at 23:15 UTC on 2031-03-04 and on 2031-03-05 on CORP-WS02.",
}
_QUESTION = "Who ran the tool on CORP-WS01, and when?"
_LEXICON = frozenset({"jane.doe", "svc-backup", "filesrv", "corp-ws01", "corp-ws02"})


def _restates_only_cited(text: str, cited: list[str]) -> bool:
    from core.entities import NamePool, unstated
    pool = NamePool.from_texts([_QUESTION] + [_BELIEFS[c] for c in cited])
    return unstated(text, pool, _LEXICON) == []


@pytest.mark.parametrize("text, cited, expected", [
    ("jane.doe ran tool.exe on CORP-WS01 at 10:15 UTC on 2031-03-02.", ["C0001"], True),
    ("The Prefetch entry shows a run count of 3.", ["C0001"], True),
    ("jane.doe ran tool.exe on CORP-WS02.", ["C0001"], False),            # a host the belief does not state
    ("The tool ran 4 times.", ["C0001"], False),                          # a number not stated
    ("jane.doe also wrote staged.7z.", ["C0001"], False),                 # a name from another belief
    ("jane.doe wrote staged.7z to FILESRV.", ["C0002"], False),           # an account the belief does not state
    ("The archive staged.7z was written on FILESRV.", ["C0002"], True),
    ("Whether data left CORP-WS01 is not established.", [], True),        # the question names the host
    ("Whether data left FILESRV is not established.", [], False),
    # recorded statements carry doubled backslashes; slashes either way; a directory
    ("It ran from C:\\Users\\jane.doe\\AppData\\Local\\Temp\\tool.exe.", ["C0001"], True),
    ("It ran from C:/Users/jane.doe/AppData/Local/Temp/tool.exe.", ["C0001"], True),
    ("The folder C:\\Users\\jane.doe held the tool.", ["C0001"], True),
    ("It was downloaded from 203.0.113.7.", ["C0001"], True),             # an address inside a URL
    ("The file is 48,512 bytes.", ["C0001"], True),                       # a thousands separator
    ("The file is 48512 bytes.", ["C0001"], True),
    ("The download ran from 10:11 to 10:14 UTC.", ["C0001"], True),       # a stated time range
    ("Hosts CORP-WS01/CORP-WS02/FILESRV connected.", ["C0002"], True),    # a slash-joined list
    ("On 2031-03-02T10:15 jane.doe ran it.", ["C0001"], True),            # a date and a shortened time joined
    ("Movement followed a CORP-WS01-centered path.", ["C0001"], True),    # a compound judged by its pieces
    ("Movement followed a CORP-WS09-centered path.", ["C0001"], False),
    ("The tool did a copy/delete of files.", ["C0001"], True),
    ("Security event 4688 recorded the run.", ["C0001"], False),          # an invented event id
    ("svc-backup ran tool.exe.", ["C0001"], False),                       # an account borrowed
    ("It ran from C:\\Users\\jane.doe\\Desktop\\tool.exe.", ["C0001"], False),   # a wrong directory
    ("It was downloaded from 203.0.113.9.", ["C0001"], False),            # a wrong address
    ("The file is 48,513 bytes.", ["C0001"], False),
    # a range is judged by its endpoints, whichever dash joins them
    ("The logons ran 23:10-23:15 UTC.", ["C0003"], True),
    ("The logons ran 23:10\u201323:15 UTC.", ["C0003"], True),
    ("The logons spanned 2031-03-04-2031-03-05.", ["C0003"], True),
    ("The logons spanned 2031-03-04\u20132031-03-05.", ["C0003"], True),
    ("The logons ran 23:10-23:20 UTC.", ["C0003"], False),                # an endpoint not stated
])
def test_unstated_holds_a_sentence_to_its_cited_texts(text, cited, expected):
    assert _restates_only_cited(text, cited) is expected


def test_names_in_reads_the_shapes_and_the_lexicon():
    from core.entities import names_in
    names = names_in("jane.doe copied 2 files to 203.0.113.7 at 10:15 from FILESRV", _LEXICON)
    assert {"jane.doe", "2", "10:15", "filesrv", "ip=203.0.113.7"} <= names
    assert "files" not in names and "copied" not in names
    assert names_in("The logons ran 23:10-23:15 UTC.", _LEXICON) >= {"23:10", "23:15"}


# A clock with a stated zone keeps it: two zoned values compare as instants,
# a zoned value and a bare clock by the written clock (the bare side states
# no zone). Invented moments in 2031.
@pytest.mark.parametrize("name, basis, expected", [
    ("10:16Z", "The upload ended 2031-03-04T10:16Z.", True),           # the zone letter of an ISO moment
    ("10:16 UTC", "The upload ended 2031-03-04T10:16:40Z.", True),     # seconds cover minutes
    ("12:16+02:00", "The upload ended 2031-03-04T10:16Z.", True),      # the same instant
    ("10:16+02:00", "The upload ended 2031-03-04T10:16Z.", False),     # two hours apart
    ("10:16:40Z", "The upload ended 2031-03-04T10:16Z.", False),       # more precise than the basis
    ("10:16Z", "The row reads 2031-03-04 10:16:40.", True),            # the basis states no zone
    ("10:16", "The upload ended 2031-03-04T10:16Z.", True),            # the name states no zone
    ("2031-03-04T05:16:40-05:00", "The upload ended 2031-03-04T10:16:40Z.", True),
    ("2031-03-05T10:16Z", "The upload ended 2031-03-04T10:16Z.", False),   # another day
    ("10:17Z", "The upload ended 2031-03-04T10:16Z.", False),
])
def test_a_zoned_clock_is_compared_with_its_zone(name, basis, expected):
    from core.entities import NamePool, names_in
    pool = NamePool.from_texts([basis])
    assert all(pool.covers(n) for n in names_in(f"It ended at {name}.")) is expected


def test_a_dash_between_two_clocks_stays_a_range():
    from core.entities import names_in
    assert names_in("between 10:16-12:00") >= {"10:16", "12:00"}
    assert "10:16:00-05:00" in names_in("at 10:16:00-05:00")
