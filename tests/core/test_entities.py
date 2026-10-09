"""Tests for core/entities.py — canonical forensic entity extraction."""
from core.entities import DISCRIMINATIVE_TYPES, discriminative, extract


class TestExtractionBasics:
    def test_ipv4_canonical_strips_port_and_leading_zeros(self):
        assert "ip:10.11.11.128" in extract("beacon to 10.11.11.128:443")
        assert "ip:10.11.11.128" in extract("connects to 10.011.011.128")

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
        ents = extract(r"staged to \\10.11.11.128\secured_drive\out.zip")
        assert "host:10.11.11.128" in ents
        assert "file:out.zip" in ents

    def test_unix_path(self):
        ents = extract("webshell at /var/www/html/shell.php found")
        assert "path:/var/www/html/shell.php" in ents
        assert "file:shell.php" in ents

    def test_registry_key(self):
        ents = extract(r"persistence via HKLM\Software\Microsoft\Windows\CurrentVersion\Run")
        assert any(e.startswith("reg:hklm/software/") for e in ents)

    def test_email_and_url(self):
        ents = extract("mail from spy.conspirator@NIST.gov see http://Evil.example/p.php.")
        assert "email:spy.conspirator@nist.gov" in ents
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

    def test_an_excerpt_cut_by_the_length_cap_still_decodes(self):
        """An excerpt is kept only up to a cap, so it usually arrives cut
        mid-string and never parses. Two encoded line breaks around a file
        format's magic string otherwise read as one name with a separator
        in it, and are reported as an account no evidence ever named."""
        from core.entities import scan_text
        cut = '{"stdout": "binary blob \\njfif\\nphotoshop 3.0 \\nsome'
        assert "account:njfif/nphotoshop" in extract(cut)
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
    assert {e for e in extract("FTP session 2004-04-26 22:21-22:26 from the host") if e.startswith("ts:")} == {"ts:2004-04-26T22:21"}
    assert "ts:2004-04-27T03:21" in extract("logged at 2004-04-26T22:21-05:00")
    assert "ts:2004-04-26T21:21" in extract("logged at 2004-04-26 22:21+0100")


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
