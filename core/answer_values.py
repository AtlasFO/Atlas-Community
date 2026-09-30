"""Typed values an answer asks for, recognised in a belief's own words.

A request part asks for one kind of thing: a date, an address, an account,
a host, a file, a hash, a time zone, an operating system, a name, a count.
This module names those kinds (``TYPES``), reads the kind a part's wording
asks for (``type_for``, a word table ordered from the most specific word to
the least), recognises values of each kind in prose (``values``), and binds
a value to a part by the clause that carries the part's own qualifying words
(``bind``): "delivery IP is 203.0.113.10; C2 IP is 198.51.100.20" answers a
delivery part and a C2 part each with its own address, and a comma-joined
"IP address 192.168.1.111, NIC MAC 0010a4933e09" gives each part the value
nearest its qualifier.

``core.entities.extract`` stays the citation extractor: it returns nothing
for bare hostnames, quoted accounts, date-only values or domains in prose,
which are the forms an answer takes.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable

TYPES = (
    "datetime", "count", "ip", "mac", "domain", "email", "account", "host", "path", "hash",
    "identifier", "zone", "os", "name", "list", "relation", "yes_no", "narrative",
)
VALUE_TYPES = frozenset(TYPES) - {"relation", "yes_no", "narrative"}

# The words a part uses to say what kind of thing it asks for, from the
# most specific to the least: "MAC" before "address", "SMTP address" before
# "address", "install date" before "when". A bare "address" names no type.
_TYPE_WORDS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(rx, re.I), kind) for rx, kind in (
        (r"\bmac(?:s|-adress\w*|\s+address(?:es)?)?\b", "mac"),
        (r"\b(?:smtp|e-?mail|mail|web-?mail)(?:\s+address(?:es)?)?\b|\bmail\s+identit|e-?mail-?adress", "email"),
        (r"\bip(?:v[46])?(?:\s+address(?:es)?)?\b|\bip-adress", "ip"),
        (r"\b(?:domains?|urls?|web\s*sites?|sites?|dom[aä]nen?)\b", "domain"),
        (r"\b(?:serial(?:\s+numbers?)?s?|guids?|volume\s+serials?|seriennummern?)\b", "identifier"),
        (r"\b(?:time\s*zones?|utc\s+offset|zeitzone)\b", "zone"),
        # A date of an installation, a shutdown, a logon or a boot is a date
        # even when the part also names the operating system it belongs to.
        (r"\b(?:install(?:ation)?\s+date|last\s+shutdown|last\s+logon|last\s+boot)\b", "datetime"),
        (r"\b(?:operating\s+systems?|\bos\b|windows\s+version|versions?|builds?|betriebssystem)\b", "os"),
        (r"\b(?:dates?|times?|timestamps?|when|wann|datum|zeitpunkt|window)\b", "datetime"),
        (r"\b(?:how\s+many|how\s+much|count|number\s+of|anzahl|wie\s*viele)\b", "count"),
        (r"\b(?:hash(?:es)?|md5|sha-?1|sha-?256|checksums?|pr[üu]fsummen?)\b", "hash"),
        # a registered owner or organisation is a name typed at setup, not an account
        (r"\bregistered\s+(?:owner|organi[sz]ation)\b|\bowners?\b|\beigent[üu]mer\b", "name"),
        (r"\b(?:accounts?|users?|usernames?|sids?|konto|konten|benutzer|logins?|credentials?|"
         r"zugangsdaten)\b", "account"),
        (r"\b(?:hosts?|host-?names?|computer\s+names?|machines?|rechner|workstations?|servers?)\b", "host"),
        (r"\b(?:files?|paths?|documents?|folders?|director(?:y|ies)|dateien?|pfade?|ordner|"
         r"executables?|binar(?:y|ies)|artefacts?|artifacts?)\b", "path"),
        (r"\b(?:prove|link|connect|correlat\w*|relat\w*|match|tie|beleg\w*|verkn[üu]pf\w*|"
         r"verbind\w*|korrelier\w*)\b", "relation"),
        (r"^(?:whether|is|are|was|were|did|does|has|have|had|can|could|any|ob|ist|sind|war|"
         r"waren|wurde|wurden|gab|gibt|hat|haben)\b", "yes_no"),
        (r"\b(?:who|whom|whose|names?|vendors?|famil(?:y|ies)|tools?|vectors?|methods?|"
         r"programs?|process(?:es)?|services?|wer|wessen)\b", "name"),
        (r"\b(?:which|list|all|every|welche[rs]?|liste|alle|histor(?:y|ies)|search(?:es)?|quer(?:y|ies)|"
         r"verlauf|suchanfragen)\b", "list"),
    ))

# The kinds whose recognised value is exact enough to print as the part's
# answer; a name or a list item is shown through its belief's headline.
STRONG_TYPES = frozenset({"datetime", "count", "ip", "mac", "domain", "email", "account", "host",
                          "path", "hash", "identifier", "zone", "os"})

# The words that say the kind rather than which one: not part of a
# qualifier. "install date" keeps "install"; "delivery IP" keeps "delivery".
# Only the generic words of a kind are dropped from a qualifier; a
# sub-kind word (SMTP, web-mail, NNTP, delivery, C2) is what tells sibling
# parts of one kind apart and stays.
_KIND_WORDS = frozenset({
    "mac", "address", "addresses", "adresse", "email", "e-mail", "mail", "mails",
    "ip", "ipv4", "ipv6", "domain", "domains", "url", "urls", "site", "sites",
    "serial", "serials", "guid", "guids", "volume", "zone", "zones", "timezone", "offset",
    "operating", "system", "os", "version", "versions", "build", "builds", "date", "dates",
    "time", "times", "timestamp", "timestamps", "when", "count", "number", "many", "hash",
    "hashes", "md5", "sha1", "sha256", "account", "accounts", "user", "users", "username",
    "usernames", "owner", "owners", "sid", "sids", "host", "hosts", "hostname", "hostnames",
    "computer", "machine", "machines", "server", "servers", "workstation", "workstations",
    "file", "files", "path", "paths", "document",
    "documents", "folder", "folders", "directory", "directories", "name", "names", "who",
    "which", "list", "all", "the", "and", "with", "its", "any", "whether", "what", "type",
})


_STOP = frozenset({
    "the", "and", "of", "to", "in", "on", "at", "is", "was", "were", "are", "for", "with", "by",
    "from", "its", "it", "an", "or", "that", "this", "which", "what", "per", "as", "be", "been",
    "has", "have", "had", "not", "no", "yes", "all", "any", "into", "over", "under", "than",
    "then", "when", "where", "who", "whom", "how", "why", "whether", "via", "during", "before",
    "after", "between", "both", "each", "other", "plus", "if", "so", "up", "out", "off", "down",
    "vs", "own", "about", "against", "whose", "also", "only", "still", "there", "their", "them",
    "they", "he", "she", "we", "you", "one", "two", "de", "der", "die", "das", "und", "oder",
    "ein", "eine", "des", "dem", "den", "mit", "von", "auf", "aus", "bei", "zu", "im", "am",
})


def _tokens(text: str) -> set[str]:
    """Content words, two characters or more (so "C2", "IP" and "DC01"
    count), without the function words of either report language."""
    toks = set(re.findall(r"[a-z0-9][a-z0-9._-]*", str(text or "").casefold()))
    return {t.strip("._-") for t in toks if len(t.strip("._-")) >= 2 and t.strip("._-") not in _STOP}


# An inflection after a stem ("planning", "installation"), with the doubled
# consonant of English spelling allowed.
_INFLECTION_RE = re.compile(r"^[a-z]?(?:ings?|ed|es|s|ers?|est|ations?|ments?|ness|ly|ungen|ung|ierungen|ierung|en|e|n|t)$")


def _same_word(a: str, b: str, core: set[str] | frozenset[str] = frozenset()) -> bool:
    """A qualifier word matches a clause word by stem: "install" matches
    "installed" and "installdate", "delivery" matches "delivered". With
    the part's ``core`` words, a compound whose tail is another word
    ("RegisteredOrganization" for "registered owner") is not the part's
    word unless that tail is one of the part's own; a file's extension
    or a separator after the stem is not a tail."""
    if a == b:
        return True
    if len(a) >= 4 and b.startswith(a):
        rest = re.sub(r"\.[a-z0-9]{1,5}$", "", b[len(a):])
        if _agent_ending(a, rest):
            return False
        if core and rest and rest[0].isalpha() and len(rest) >= 4 and not _INFLECTION_RE.match(rest) \
                and rest not in core and not any(rest.startswith(c) or c.startswith(rest) for c in core if len(c) >= 3):
            return False
        return True
    return len(b) >= 4 and a.startswith(b) and not _agent_ending(b, a[len(b):])


def _agent_ending(stem: str, rest: str) -> bool:
    """``rest`` after ``stem`` is an "-er" ending (the stem's last consonant
    may double): the doer or the tool, another thing than the stem names -
    the installer is not the install, the downloader not the download."""
    if rest[:1] == stem[-1:] and rest[1:] in ("er", "ers"):
        return True
    return rest in ("er", "ers")


def _overlap(qual: set[str], words: set[str], core: set[str] | frozenset[str] = frozenset()) -> int:
    return sum(1 for q in qual if any(_same_word(q, w, core) for w in words))


_RELATIVE_TAIL_RE = re.compile(r"(?i)\s+(?:that|which|whose|where|who|whom)\s+.*$")


def type_for(part_text: str) -> str | None:
    """The kind of value ``part_text`` asks for, or None when its words name
    no kind (a bare "address", a phrase with no kind word). The part's head
    names it before a relative clause that describes it: "the artefact that
    binds the account" asks for an artefact, not an account."""
    text = " ".join(str(part_text or "").split())
    head = _RELATIVE_TAIL_RE.sub("", text)
    for candidate in dict.fromkeys((head, text)):
        for rx, kind in _TYPE_WORDS:
            if rx.search(candidate):
                return kind
    return None


_TAIL_RE = re.compile(r"(?i)\s+(?:that|which|whose|where|who|whom|against|during|on|in|to|of|for|from|with|by|at|per|into)\s+.*$")


def qualifier(part_text: str) -> set[str]:
    """The part's own words beyond the kind it names: what tells its value
    from another value of the same kind. The core of the part (its words
    before a relative clause or a prepositional tail) is what a clause
    must carry; the tail only describes it."""
    core = _TAIL_RE.sub("", " ".join(str(part_text or "").split()))
    words = {t for t in _tokens(core) if t not in _KIND_WORDS}
    if words:
        return words
    return {t for t in _tokens(part_text) if t not in _KIND_WORDS}


# ── recognisers ───────────────────────────────────────────────────────────

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b|\b[0-9A-Fa-f]{12}\b")
_TLDS = (
    "com|net|org|edu|gov|mil|int|info|biz|name|pro|io|co|eu|us|uk|de|fr|nl|ru|cn|jp|kr|"
    "br|au|ca|ch|at|se|no|dk|fi|pl|cz|es|it|be|ie|pt|gr|hu|ro|tr|in|mx|ar|za|nz|sg|hk|tw|"
    "local|onion|internal|lan|corp|home"
)
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r")\b(?![\w.-]*\.[a-z]{2,4}\b(?:$|[^\w.]))")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b(?![\w.-]*\[\d+\])")
_DOMAIN_USER_RE = re.compile(r"\b([A-Za-z][\w-]{1,30})\\([A-Za-z][\w.$-]{1,30})\b(?!\\)")
_SID_RE = re.compile(r"\bS-1-\d+(?:-\d+){1,14}\b")
# A quoted principal follows its cue directly ("account 'jdoe'") or a
# naming verb after it ("the user of the notebook is 'Mr. Smith'"); a quoted
# title elsewhere in the sentence is not a name.
_QUOTED_PRINCIPAL_RE = re.compile(
    r"(?i)\b(?:accounts?|users?|usernames?|profiles?|principals?|konto|benutzer|(?:logon|login)\s+names?)\b"
    r"(?:(?:\s+[\w.$\\-]+){0,6}?\s+(?:named|called|names?|is|was|ist|war|heißt|lautet|:|=))?"
    r"\s+['\"‘’“”]([^'\"‘’“”]{2,40})['\"‘’“”]")
# "the main user of the notebook is Mr. Smith", "the account was MrSmith":
# after an account cue and a copula, a capitalised name of one or two
# words (a title's stop allowed) is the account, quoted or not.
_COPULA_PRINCIPAL_RE = re.compile(
    r"(?i)\b(?:accounts?|users?|usernames?|profiles?|principals?|konto|benutzer|(?:logon|login)\s+names?)\b"
    r"(?:\s+[\w.$\\-]+){0,7}?\s+(?:is|was|were|ist|war|heißt|lautet|=|:)\s+"
    r"(?:['\"‘’“”](?P<quoted>[^'\"‘’“”]{2,40})['\"‘’“”]|"
    r"(?P<bare>(?-i:[A-Z][a-z]{0,3}\.\s+[A-Z][\w$-]+|[A-Z][\w$-]+(?:\s+[A-Z][\w$-]+)?)))")
_LOCATION_NOUN_RE = re.compile(
    r"(?i)\b(?:folders?|director(?:y|ies)|paths?|locations?|files?|drives?|shares?|"
    r"ordner|pfade?|verzeichnis(?:se)?|dateien?|laufwerke?)\b")
_TITLE_STOP_RE = re.compile(r"^([A-Z][a-z]{0,3})\.\s+([A-Z][\w$-]*)")
_PATH_ON_RE = re.compile(r"^\.?\s+[^\s\\,;]+\\")


def _title_stop(name: str) -> str:
    """"Mr. The": a short title's stop before a function word ends the
    sentence; the name is the title alone."""
    m = _TITLE_STOP_RE.match(name)
    if m and m.group(2).lower() in _STOP:
        return m.group(1)
    return name


def _continues_name_or_path(user: str, after: str) -> bool:
    """The text after a DOMAIN\\user match goes on as a path ("Settings\\
    J Doe\\...") or as a titled name ("Settings\\Mr. Smith"): the match is a
    cut path segment, not an account."""
    if _PATH_ON_RE.match(after):
        return True
    m = _TITLE_STOP_RE.match(user + after)
    return bool(m) and m.group(1) == user and m.group(2).lower() not in _STOP


_NOT_A_NAME = frozenset({
    "windows", "microsoft", "the", "this", "that", "not", "unknown", "none", "n/a", "local",
    "domain", "administrator", "system", "guest", "a", "an",
    # logon types and outcome words are attributes of a logon, not names
    "interactive", "network", "batch", "service", "unlock", "networkcleartext", "newcredentials",
    "remoteinteractive", "cachedinteractive", "successful", "success", "failed", "failure",
    "enabled", "disabled", "locked", "active", "inactive", "expired",
})
# Words that follow "account" or "user" in prose without naming one.
_NOT_A_PRINCIPAL = frozenset({
    "creation", "created", "name", "names", "via", "on", "in", "that", "which", "with", "the",
    "was", "is", "and", "or", "for", "of", "to", "from", "by", "per", "used", "logged", "deleted",
    "has", "had", "profile", "profiles", "account", "accounts", "activity", "data", "folder",
    "level", "rights", "id", "ids", "sid", "sids", "list", "management", "control", "lockout",
    "policy", "settings", "enumeration", "discovery", "logon", "login", "takeover", "abuse",
})
_HOSTLIKE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]{1,15}-[A-Za-z0-9]{1,20}\d\b")
# An upper-case hyphenated name with a digit somewhere (DESKTOP-SDN1RPT,
# N-1A9ODN6ZXK4LQ, CITADEL-DC01), never a technique or vulnerability id.
_UPPER_HYPHEN_HOST_RE = re.compile(r"\b(?!CVE-|MS\d\d-|T\d{4})[A-Z][A-Z0-9]{0,15}-[A-Z0-9]{2,20}\b")
_UPPER_HOST_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,14}\d\b")
_FQDN_RE = re.compile(r"(?i)\b[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,5}\.(?:" + _TLDS + r")\b")
_NODE_ID_RE = re.compile(r"(?i)^(?:[A-Z]\d{4}|task-\d{4}|F-\d{3})$")
# Tokens shaped like a bare upper-case host name that name a format, a hash
# algorithm, a service pack, an architecture, a protocol or a unit instead.
_TECH_TOKENS = frozenset({
    "E01", "EX01", "E02", "EWF", "DD", "RAW", "AFF", "VMDK", "VHD", "VHDX", "ISO", "MD5", "SHA1",
    "SHA256", "SHA512", "CRC32", "SP1", "SP2", "SP3", "SP4", "X64", "X86", "AMD64", "ARM64", "IA64",
    "NTFS", "FAT12", "FAT16", "FAT32", "EXFAT", "UTC", "GMT", "RID", "SID", "PID", "UID", "GID",
    "ID", "IP", "IPV4", "IPV6", "MAC", "USB", "CD", "DVD", "CDR", "RAM", "ROM", "GB", "MB", "KB",
    "TB", "IE", "IE6", "IE7", "IE8", "MS", "OS", "PE", "PE32", "DLL", "EXE", "ZIP", "RAR", "TS",
    "EVTX", "EVT", "CSV", "XML", "TSV", "PST", "OST", "MFT", "USN", "LNK", "PF", "AWS", "S3",
    "T1", "Q1", "Q2", "Q3", "Q4", "H1", "H2", "V1", "V2", "PC", "RM", "RM1", "RM2", "RM3", "TCP",
    "UDP", "HTTP", "HTTPS", "FTP", "SMB", "RDP", "SSH", "DNS", "DHCP", "C2", "VPN", "VPS",
    "POP3", "IMAP", "IMAP4", "SMTP", "NNTP", "LDAP", "NTLM", "SSL", "TLS", "HTML", "HTML5", "UTF8",
})
# Identifiers shaped like host names that are not hosts.
_NOT_HOST_RE = re.compile(r"(?i)^(?:CVE-|MS\d\d-|T\d{4}(?:\.\d{3})?$|KB\d+$|RID-?\d)")
_RID_NAME_RE = re.compile(r"\b([A-Z][\w.'’-]+(?:\s+[A-Z][\w.'’-]+)?)\s*\(RID\s*\d+\)")
_WELL_KNOWN_ACCOUNTS = frozenset({
    "administrator", "administrateur", "guest", "system", "root", "krbtgt", "defaultaccount",
    "defaultuser0", "wdagutilityaccount", "helpassistant", "support_388945a0",
})
# A time keeps the zone words that follow it: "UTC", "Z", an offset, "local
# time" or "<host> time", so a local time never reads as UTC in a report.
_ISO_DT_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?"
    r"(?:\s?(?:Z\b|UTC\b|GMT\b|[+-](?:0\d|1[0-4]):?[0-5]\d\b|local(?:\s+time)?\b|"
    r"[A-Za-z][\w-]{1,15}\s+(?:local\s+)?time\b))?)?")
_UTC_MARK_RE = re.compile(r"(?i)\b(?:utc|gmt|z)\b|[+-]00:?00\b")
_MONTHS = ("january|february|march|april|may|june|july|august|september|october|november|december|"
           "jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec|"
           "januar|februar|märz|maerz|mai|juni|juli|oktober|dezember")
_WORD_DATE_RE = re.compile(
    r"(?i)\b(?:\d{1,2}\.?\s+(?:" + _MONTHS + r")\.?\s+\d{4}|(?:" + _MONTHS + r")\.?\s+\d{1,2},?\s+\d{4})\b")
_HASH_RE = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
# A Windows path whose segments may carry spaces ("C:\\FileShare\\Secret\\Szechuan
# Sauce.txt"): the final segment ends at an extension; a directory path keeps
# the no-space form.
_WIN_PATH_RE = re.compile(
    r"\b[A-Za-z]:\\(?:[^\\:*?\"<>|\s][^\\:*?\"<>|\n]*?\\)*[^\\:*?\"<>|\s][^\\:*?\"<>|\n]*?\.[A-Za-z0-9]{1,5}(?=[\s,;:)\]\"']|\.(?:\s|$)|$)"
    r"|\b[A-Za-z]:\\(?:[^\\:*?\"<>|\s][^\\:*?\"<>|\n]*?\\)+"
    r"|\b[A-Za-z]:\\(?:[^\\\s:*?\"<>|]+\\)*[^\\\s:*?\"<>|]*")
_QUOTED_FILE_RE = re.compile(r"[\"“‘']([^\"”’'\n]{1,120}?\.[A-Za-z0-9]{1,5})[\"”’']")
_UNIX_PATH_RE = re.compile(r"(?<![\w.])/(?:[\w.+-]+/)+[\w.+-]+")
# A relative forward-slash path as prose writes a profile folder
# ("Documents and Settings/J Doe/NTUSER.DAT"): at least two separators, and
# it ends in a file name with a known extension or at a separator. A segment
# is one word, or capitalised words joined by single spaces with at most one
# short lower-case word among them ("Documents and Settings"), so the prose
# before the path mostly stays out of it; "and/or", "TCP/IP", a date or a
# time-zone name is no path. Ceiling: a capitalised word and one short word
# just before a path ("Found in Windows/...") join its first segment.
_REL_WORD = r"[^\s/\\,;:()\"'<>|]+"
_REL_CAP_WORD = r"[A-Z0-9][^\s/\\,;:()\"'<>|]*"
_REL_SEG = (rf"(?:{_REL_CAP_WORD}(?: {_REL_CAP_WORD})*(?: [a-z]{{1,3}}(?: {_REL_CAP_WORD})+)?"
            rf"|{_REL_WORD})")
_REL_SLASH_PATH_RE = re.compile(rf"(?<![\w./\\:@-])((?:{_REL_SEG}/){{2,}})({_REL_SEG})?")
# CamelCase registry value names ("RegisteredOwner", "CurrentVersion") and
# the hive names label a value; neither is a person's or a thing's name.
_REGISTRY_LABEL_RE = re.compile(r"^(?:[A-Z][a-z]+){2,}$|^(?:SOFTWARE|SYSTEM|SAM|SECURITY|NTUSER(?:\.DAT)?|USRCLASS(?:\.DAT)?|DEFAULT)$")
_NETBIOS_DOMAIN_RE = re.compile(
    r"(?i)\b(?:primary\s+|logon\s+)?(?:domain|workgroup|dom[aä]ne|arbeitsgruppe)\b"
    r"(?:\s+(?:name|is|was|=|:|ist|lautet|heißt))*\s+['\"‘’“”]?(?-i:([A-Z][A-Z0-9-]{1,14}))['\"‘’“”]?(?![\w.-])")
_FILENAME_RE = re.compile(r"\b(?=[\w#@$-]{0,63}[A-Za-z])[\w#@$()\[\]-]{1,64}\.(?:[A-Za-z0-9]{1,5})\b")
_GUID_RE = re.compile(r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?")
_VOLUME_SERIAL_RE = re.compile(r"\b[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\b")
_SERIAL_RE = re.compile(r"(?i)\b(?:serial(?:\s+number)?|s/n|seriennummer)\s*[:#]?\s*([A-Za-z0-9&_{}\-]{6,64})")
_ZONE_RE = re.compile(
    r"\b(?:[A-Z][a-z]+(?: [A-Z][a-z]+)? (?:Standard|Daylight|Summer) Time|UTC\s?[+-]\s?\d{1,2}(?::\d{2})?|"
    r"GMT\s?[+-]\s?\d{1,2}(?::\d{2})?|(?:Europe|America|Asia|Africa|Australia|Pacific|Atlantic)/[A-Za-z_]+|"
    r"CE[S]?T|EE[S]?T|WE[S]?T|[ECMP][SD]T|AK[SD]T|H[SD]T|MEZ|MESZ)\b|\bBias\s*[:=]?\s*-?\d{1,4}\b")
_OS_RE = re.compile(
    r"\b(?:Windows\s+(?:XP|Vista|7|8(?:\.1)?|10|11|2000|NT|Server\s+\d{4}(?:\s+R2)?)(?:\s+(?:Professional|Home|Pro|"
    r"Enterprise|Ultimate|Education|Datacenter|Standard|Evaluation))*(?:\s+(?:SP|Service Pack)\s?\d)?|"
    r"Ubuntu\s+\d+\.\d+|Debian\s+\d+|CentOS\s+\d+|macOS\s+[\d.]+|build\s+\d+(?:\.\d+)*|"
    r"\d+\.\d+\.\d{4,5}(?:\.\d+)?)\b")
_NUMBER_RE = re.compile(
    r"(?i)\b(?:\d{1,6}|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|none|zero|"
    r"ein|eine|einen|zwei|drei|vier|fünf|sechs|sieben|acht|neun|zehn|elf|zwölf|keine?|null)\b")
_NAME_RE = re.compile(r"\b(?:[A-Z][\w'’.-]+(?:\s+[A-Z][\w'’.-]+){0,3})\b|['\"‘“]([^'\"‘’“”]{2,60})['\"’”]")
_ARTIFACT_TOKEN_RE = re.compile(r"\b[\w$#@-]{2,64}\.(?:[A-Za-z0-9]{1,5})\b")


def _valid_ipv4(token: str) -> bool:
    try:
        ipaddress.IPv4Address(token)
        return True
    except ValueError:
        return False


def _valid_ipv6(token: str) -> bool:
    try:
        ipaddress.IPv6Address(token)
        return True
    except ValueError:
        return False


def _spans(rx: re.Pattern[str], text: str, group: int = 0):
    for m in rx.finditer(text):
        val = m.group(group) if group else m.group(0)
        if val:
            yield val, m.start(group) if group else m.start()


_NAME_PART_RE = re.compile(r"(?i)\b(?:computer|host|machine|system)\s*names?\b|\bhostnames?\b|\brechnername")


def _relative_slash_paths(text: str, exts: Iterable[str]) -> list[tuple[str, int]]:
    """The relative forward-slash paths of ``text`` (_REL_SLASH_PATH_RE):
    one that ends in a segment keeps the longest run of that segment's words
    ending in a known extension; one without such a file ends at its last
    separator, and only when no name follows it there."""
    out: list[tuple[str, int]] = []
    for m in _REL_SLASH_PATH_RE.finditer(text):
        head, tail = m.group(1), m.group(2)
        if tail:
            words = tail.split(" ")
            keep = next((i for i in range(len(words), 0, -1)
                         if words[i - 1].rstrip(".").rsplit(".", 1)[-1].lower() in exts
                         and "." in words[i - 1].rstrip(".")), 0)
            if keep:
                out.append((head + " ".join(words[:keep]).rstrip("."), m.start()))
            continue
        if not re.match(r"\w", text[m.end():m.end() + 1]):
            out.append((head, m.start()))
    return out


def _extend_file_name(text: str, start: int) -> int:
    """A bare file name whose words carry spaces ("Operation 2nd Hand
    Smoke.pptx"): the start moves back over preceding capitalised or
    numeric words joined by single spaces, up to punctuation or a
    lower-case word."""
    pos = start
    while pos >= 2 and text[pos - 1] == " ":
        m = re.search(r"(?:^|(?<=[\s(\[\"“']))([A-Z0-9][\w'’-]*)$", text[:pos - 1])
        if not m:
            break
        pos = m.start(1)
    return pos


# A path separator, then at most one more word of the same segment, right
# before a position ("...\\Users\\" before "jdoe", "/Login " before "Data"). A
# segment of a Windows path often holds one space ("User Data", "Login
# Data"); prose after a path runs longer and is not caught.
_PATH_SEGMENT_TAIL_RE = re.compile(r"[\\/][\w.$-]*(?: [\w.$-]+)? ?$")


def _continues_path_segment(text: str, pos: int) -> bool:
    """Whether the value at ``pos`` is part of a path segment rather than
    prose."""
    return bool(_PATH_SEGMENT_TAIL_RE.search(text[max(0, pos - 64):pos]))


def values(text: str, kind: str, *, known_hosts: Iterable[str] = (), exclude: Iterable[str] = (),
           name_part: bool = False) -> list[tuple[str, int]]:
    """The values of ``kind`` in ``text``, each with its character offset,
    in text order. ``known_hosts`` are the case's host names (for the host
    kind): they lead the host values, except for a computer-name part
    (``name_part``), where a label the run chose counts only where the
    clause names it as the computer or host name; ``exclude`` are words
    that do not count as a value (the words of the question, for names and
    lists)."""
    text = str(text or "")
    out: list[tuple[str, int]] = []
    if kind == "ip":
        out += [(v, p) for v, p in _spans(_IPV4_RE, text) if _valid_ipv4(v)]
        out += [(v, p) for v, p in _spans(_IPV6_RE, text) if _valid_ipv6(v)]
    elif kind == "mac":
        for v, p in _spans(_MAC_RE, text):
            if len(v) == 12 and not re.search(r"[A-Fa-f]", v) and v.isdigit() and len(set(v)) <= 2:
                continue  # a run of digits is a count, not an address
            out.append((v, p))
    elif kind == "domain":
        from core.entities import domain_spans
        out += [(v.rstrip(";,.)]"), p) for v, p in _spans(_URL_RE, text)]
        out += domain_spans(text)
        # a NetBIOS domain or workgroup has no dots: it counts after its cue
        out += [(m.group(1), m.start(1)) for m in _NETBIOS_DOMAIN_RE.finditer(text)]
    elif kind == "email":
        out += list(_spans(_EMAIL_RE, text))
    elif kind == "account":
        out += [(f"{m.group(1)}\\{m.group(2)}", m.start()) for m in _DOMAIN_USER_RE.finditer(text)
                if not _continues_name_or_path(m.group(2), text[m.end():])]
        out += list(_spans(_SID_RE, text))
        out += [(v, p) for v, p in _spans(_QUOTED_PRINCIPAL_RE, text, 1)
                if v.lower().split()[0].rstrip(".") not in _NOT_A_NAME]
        for m in _COPULA_PRINCIPAL_RE.finditer(text):
            grp = "quoted" if m.group("quoted") else "bare"
            if _LOCATION_NOUN_RE.search(text[m.start():m.start(grp)]):
                continue  # "the profile folder is X": X is a place, not an account
            name = _title_stop(m.group(grp).strip().rstrip(",;"))
            if name.lower().split()[0].rstrip(".") not in _NOT_A_NAME and not _SID_RE.fullmatch(name):
                out.append((name, m.start(grp)))
        out += [(v, p) for v, p in _spans(_RID_NAME_RE, text, 1)]
        for m in re.finditer(r"\b[A-Za-z][\w$-]{2,30}\b", text):
            tok = m.group(0)
            if tok.lower() not in _WELL_KNOWN_ACCOUNTS:
                continue
            # A well-known name counts when written as one: "Administrator",
            # "Guest", "SYSTEM"; the words "system" and "root" in prose are
            # not accounts.
            if tok.lower() in ("system", "root"):
                # "SYSTEM" is also a hive and "root" a folder: only written
                # as a principal ("account SYSTEM", "NT AUTHORITY\SYSTEM",
                # "as SYSTEM", "LocalSystem") does it count.
                if re.search(r"(?i)(?:account|user|authority\\|as|local)\s*" + re.escape(tok) + r"\b", text):
                    out.append((tok, m.start()))
            elif tok[0].isupper():
                out.append((tok, m.start()))
        # "user named X" / "account called X": X is the name.
        for m in re.finditer(r"(?i)\b(?:accounts?|users?|usernames?|profiles?|principals?|logins?)\s+"
                             r"(?:named|called|namens)\s+['\"‘’“”]?([A-Za-z][\w.$\\-]{1,63})", text):
            out.append((m.group(1), m.start(1)))
        try:
            from core.ioc_catalog import _NAMED_USER_RE, written_as_principal
            for m in _NAMED_USER_RE.finditer(text):
                tok = m.group(1).rstrip(".")      # a sentence-final stop is not part of the name
                if tok.lower() in ("named", "called", "namens") or tok.lower() in _NOT_A_NAME:
                    continue
                if written_as_principal(tok, text):
                    out.append((tok, m.start(1)))
        except Exception:  # noqa: BLE001 - the catalog's readers are an aid, not a need
            pass
        # A folder or file name is not an account: "C:\\Users\\jdoe\\Desktop"
        # holds no "jdoe\\Desktop", nor "Default/Login Data" a user "Data".
        # A SID stays an account wherever it is written: a registry path
        # names the account by it (...\\ProfileList\\S-1-5-21-...-1001).
        out = [(v, p) for v, p in out if _SID_RE.fullmatch(v) or not _continues_path_segment(text, p)]
    elif kind == "host":
        known = {h.strip().lower() for h in known_hosts if h and h.strip()}
        out += [(v, p) for v, p in _spans(_HOSTLIKE_RE, text)
                if not _NODE_ID_RE.match(v) and not _NOT_HOST_RE.match(v)]
        out += [(v, p) for v, p in _spans(_UPPER_HYPHEN_HOST_RE, text)
                if re.search(r"\d", v) and not _NOT_HOST_RE.match(v)
                and not _MAC_RE.fullmatch(v) and not _VOLUME_SERIAL_RE.fullmatch(v)]
        out += [(v, p) for v, p in _spans(_UPPER_HOST_RE, text)
                if not _NODE_ID_RE.match(v) and not _NOT_HOST_RE.match(v) and not _HASH_RE.fullmatch(v)
                and len(v) >= 4 and sum(ch.isalpha() for ch in v) >= 2]
        out += [(v, p) for v, p in _spans(_FQDN_RE, text) if not _EMAIL_RE.search(v)]
        out = [(v, p) for v, p in out if v.upper() not in _TECH_TOKENS and not _NODE_ID_RE.match(v)]
        if known:
            def _named_as_name(tok: str) -> bool:
                esc = re.escape(tok)
                return bool(re.search(r"(?i)\b(?:computer|host|machine|system)\s*names?\s*(?:is|was|:|=)?\s*"
                                      + esc + r"\b|\bhostnames?\s*(?:is|was|:|=)?\s*" + esc
                                      + r"\b|\bnamed\s+" + esc + r"\b", text))
            named = [(m.group(0), m.start()) for m in re.finditer(r"[\w.-]+", text)
                     if m.group(0).lower() in known and (not name_part or _named_as_name(m.group(0)))]
            out = named + [(v, p) for v, p in out if v.lower() not in known]
    elif kind == "path":
        try:
            from core.ioc_catalog import _KNOWN_FILE_EXT as _exts
        except Exception:  # noqa: BLE001
            _exts = frozenset()
        quoted = [(v, p) for v, p in _spans(_QUOTED_FILE_RE, text, 1)
                  if not _exts or v.rsplit(".", 1)[-1].lower() in _exts]
        taken = [(p, p + len(v)) for v, p in quoted]
        def _inside(pos: int) -> bool:
            return any(a <= pos < b for a, b in taken)
        out += quoted
        paths = [(v, p) for v, p in _spans(_WIN_PATH_RE, text) if not _inside(p)]
        paths += [(v, p) for v, p in _spans(_UNIX_PATH_RE, text) if not _inside(p)]
        taken += [(p, p + len(v)) for v, p in paths]
        paths += [(v, p) for v, p in _relative_slash_paths(text, _exts) if not _inside(p)]
        taken += [(p, p + len(v)) for v, p in paths]
        out += paths
        for v, p in _spans(_FILENAME_RE, text):
            if _inside(p) or _valid_ipv4(v) or _DOMAIN_RE.fullmatch(v):
                continue
            if _exts and v.rsplit(".", 1)[-1].lower() not in _exts:
                continue
            start = _extend_file_name(text, p)
            out.append((text[start:p] + v, start))
    elif kind == "hash":
        out += list(_spans(_HASH_RE, text))
    elif kind == "identifier":
        out += list(_spans(_GUID_RE, text))
        out += [(v, p) for v, p in _spans(_SERIAL_RE, text, 1)]
        out += list(_spans(_VOLUME_SERIAL_RE, text))
    elif kind == "datetime":
        hits = list(_spans(_ISO_DT_RE, text)) + list(_spans(_WORD_DATE_RE, text))
        # When a clause gives a time in UTC and one in a local zone, the
        # UTC one is the answer.
        utc = [(v, p) for v, p in hits if _UTC_MARK_RE.search(v)]
        out += utc + [(v, p) for v, p in hits if (v, p) not in utc]
    elif kind == "zone":
        out += list(_spans(_ZONE_RE, text))
    elif kind == "os":
        out += list(_spans(_OS_RE, text))
    elif kind == "count":
        out += list(_spans(_NUMBER_RE, text))
    elif kind == "name":
        skip = {w.lower() for w in exclude} | {h.lower() for h in known_hosts}
        for m in _NAME_RE.finditer(text):
            v = m.group(1) or m.group(0)
            if v.lower() in skip or len(v) < 2 or _valid_ipv4(v) or _NODE_ID_RE.match(v):
                continue
            if any(_REGISTRY_LABEL_RE.match(w) for w in v.split()):
                continue          # a registry value name or a hive name labels a value, it is not one
            if m.group(1) is None and m.start() == 0 and v.lower() in ("the", "a", "an", "on", "in", "at"):
                continue
            out.append((v, m.start()))
    elif kind == "list":
        for k in ("path", "ip", "email", "account", "host", "hash", "domain", "mac", "identifier", "datetime"):
            out += values(text, k, known_hosts=known_hosts)
        out += [(v, p) for v, p in _spans(_ARTIFACT_TOKEN_RE, text)]
    # de-duplicate by offset, keep text order, except that a host named as
    # the machine's name and a time given in UTC come first whatever their
    # offset, so a first-value choice prefers them
    known = {h.strip().lower() for h in known_hosts if h and h.strip()}

    def _rank(item: tuple[str, int]) -> tuple[int, int]:
        v, p = item
        first = ((kind == "host" and v.lower() in known)
                 or (kind == "datetime" and bool(_UTC_MARK_RE.search(v))))
        return (0 if first else 1, p)
    seen: set[int] = set()
    ordered: list[tuple[str, int]] = []
    for v, p in sorted(out, key=_rank):
        if p in seen:
            continue
        seen.add(p)
        ordered.append((v, p))
    return ordered


# ── binding ───────────────────────────────────────────────────────────────

_CLAUSE_SPLIT_RE = re.compile(r";\s+|:\s+|(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def clauses(text: str) -> list[tuple[str, int]]:
    """The clauses of ``text`` with their offsets: split at semicolons, at a
    colon followed by a space, and at sentence ends. A stop that closes a
    title, an initial or a common abbreviation ("Mr. Smith", "J. Doe",
    "approx. 5") is inside the clause, not its end."""
    from core.answer_synthesis import _ABBREVIATION_TAIL_RE
    text = str(text or "")
    out: list[tuple[str, int]] = []
    pos = 0
    for m in _CLAUSE_SPLIT_RE.finditer(text):
        if m.group(0).strip() == "" and _ABBREVIATION_TAIL_RE.search(text[:m.start()]):
            continue
        piece = text[pos:m.start()]
        if piece.strip():
            out.append((piece, pos))
        pos = m.end()
    tail = text[pos:]
    if tail.strip():
        out.append((tail, pos))
    return out


def first_sentence_span(text: str) -> tuple[str, int]:
    try:
        from core.answer_synthesis import first_sentence
        first = first_sentence(str(text or ""))
    except Exception:  # noqa: BLE001
        first = str(text or "").split(". ", 1)[0]
    return first, 0


def _token_positions(text: str, words: set[str], core: set[str] | frozenset[str] = frozenset()) -> list[int]:
    out = []
    for m in re.finditer(r"[a-z0-9][a-z0-9._-]*", text.casefold()):
        tok = m.group(0).strip("._-")
        if len(tok) >= 2 and any(_same_word(q, tok, core) for q in words):
            out.append(m.start())
    return out


_ABSENT_RE = re.compile(r"(?i)\b(?:not (?:recorded|set|available|found|present|known|stated|determined|given)"
                        r"|unknown|none|n/a|nicht (?:vorhanden|gesetzt|bekannt|verf(?:ü|ue)gbar|ermittelt|angegeben)"
                        r"|unbekannt)\b")


def _denies(text: str, opening: bool = False) -> bool:
    """Whether ``text`` says the value is absent: an absence phrase or a
    negator anywhere in a label ("Install date not recorded:"), or among
    the opening words of a value clause ("not recorded, the account was
    created on ...")."""
    from core.ir_playbook import _NEGATORS
    head = " ".join(text.split()[:4]) if opening else text
    if _ABSENT_RE.search(head) or re.search(r"n't\b", head):
        return True
    return any(w in _NEGATORS for w in re.findall(r"[a-zäöüß]+", head.casefold()))


def _count_near_noun(clause: str, qual: set[str], hits: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """A count is the number next to the counted noun (the qualifier), not
    a year or a record number elsewhere in the clause."""
    noun_positions = _token_positions(clause, qual) if qual else []
    if not noun_positions:
        return [h for h in hits if not re.fullmatch(r"(?:19|20)\d{2}", h[0])]
    out = []
    for v, p in hits:
        if re.fullmatch(r"(?:19|20)\d{2}", v):
            continue
        if any(abs(_token_index(clause, p) - _token_index(clause, n)) <= 3 for n in noun_positions):
            out.append((v, p))
    return out


def _token_index(text: str, offset: int) -> int:
    return len(re.findall(r"\S+", text[:offset]))


# A shortcut or metadata artifact is evidence about a file, not the file:
# for a path part it never wins over a non-shortcut path in the same clause.
_SHORTCUT_RE = re.compile(r"(?i)(?:\.(?:lnk|pf|url|customdestinations-ms|automaticdestinations-ms)$|thumbcache|thumbs\.db)")


def _shortcut(value: str) -> int:
    return 1 if _SHORTCUT_RE.search(value or "") else 0


def _nearness(clause: str, value_pos: int, qpos: list[int],
              value_len: int = 0, qual: set[str] = frozenset(),
              others: list[tuple[int, int]] = ()) -> tuple[int, int]:
    """How near a value sits to the part's qualifier words: a value that
    carries a qualifier word among its own words first (0, 0), then one
    whose own name merely starts with the word (0, 1), then a value after
    the qualifier ("NNTP server news.example.net"), then one ahead of it,
    each by token distance. A qualifier word inside another value of the
    clause is that value's name, not prose, and anchors no neighbour."""
    vi = _token_index(clause, value_pos)
    best = None
    stem = False
    for q in qpos:
        if value_len and value_pos <= q < value_pos + value_len:
            # A multi-word value ("Secret Recipe.txt") starts before the
            # qualifier word it contains; read by its start alone it would
            # rank behind the next value in a list. Only a whole word is the
            # value's own: "RegisteredOwner" carries no word "registered".
            if _exact_word_at(clause, q, qual):
                return (0, 0)
            stem = True
            continue
        if any(a <= q < b for a, b in others if a != value_pos):
            continue
        qi = _token_index(clause, q)
        key = (0 if vi >= qi else 1, abs(vi - qi))
        if best is None or key < best:
            best = key
    if stem and (best is None or (0, 1) < best):
        return (0, 1)
    return best or ((0, 0) if not qpos else (2, 0))


def _exact_word_at(clause: str, pos: int, qual: set[str]) -> bool:
    """Whether the token at ``pos`` is one of the qualifier words itself (a
    file's extension set aside), not a longer name that starts with one."""
    m = re.match(r"[A-Za-z0-9._-]+", clause[pos:])
    tok = (m.group(0) if m else "").strip("._-").casefold()
    if re.search(r"\.[a-z0-9]{1,5}$", tok):
        tok = tok.rsplit(".", 1)[0]
    return bool(tok) and (tok in qual or any(_same_word(q, tok) and len(tok) <= len(q) + 2 for q in qual))


def _rank(kind: str, clause: str, value: str, pos: int, qpos: list[int], qual: set[str] = frozenset(),
          others: list[tuple[int, int]] = ()) -> tuple:
    """The order among a clause's values of one kind: for a path part a
    shortcut behind every real file, then nearness to the qualifier, then
    the fuller form ("C:\\Share\\Secret Recipe.txt" over "Secret Recipe.txt"
    when both carry the qualifier word). ``others`` are the spans of every
    value of the kind in the clause."""
    if kind == "path":
        return (_shortcut(value), _nearness(clause, pos, qpos, len(value), qual, others), -len(value))
    return (0, _nearness(clause, pos, qpos, len(value), qual, others))


# A part that asks where something is wants a location: a file name without
# a folder does not say where.
_WHERE_RE = re.compile(r"(?i)^(?:where|wo)\b")


def bind(part_text: str, kind: str, statement: str, *, question: str = "",
         known_hosts: Iterable[str] = (), explicit: bool = False,
         prefer: Iterable[str] = ()) -> tuple[str | None, str]:
    """The value of ``kind`` in ``statement`` that answers the part, with
    the clause it came from, or ``(None, "")``.

    With a qualifier (the part's words beyond its kind), the value must come
    from a clause that carries the qualifier; among several values of the
    kind in that clause the one nearest the qualifier by token distance is
    taken. Without a qualifier the value must sit in the statement's first
    sentence.

    ``prefer`` holds the values the belief itself types as indicators of
    this kind. Within the clause a path settles on, a preferred value ranks
    before any other, whatever the word distance: "a channel from HOST
    (10.0.0.5) to 203.0.113.9" names two addresses, and the analyst's typed
    indicator says which one the belief is about. Which clause answers is
    decided as before.
    """
    if kind not in VALUE_TYPES:
        return None, ""
    statement = str(statement or "")
    preferred = {str(v).strip().lower() for v in prefer if str(v).strip()}

    def untyped(value: str) -> bool:
        return value.lower() not in preferred

    qual = qualifier(part_text)
    core = _tokens(part_text)
    exclude = set(re.findall(r"[\w'’.-]+", question or "")) | set(re.findall(r"[\w'’.-]+", part_text or ""))
    name_part = kind == "host" and bool(_NAME_PART_RE.search(part_text or ""))
    where = kind == "path" and bool(_WHERE_RE.match(" ".join(str(part_text or "").split())))

    def values(text, kind, **kw):   # noqa: F811 - the module's values, narrowed for a where-part
        hits = _values(text, kind, **kw)
        return [h for h in hits if not where or re.search(r"[\\/]", h[0])]

    if explicit:
        # The analyst named the belief for this part: a value of the kind
        # suffices, the one nearest a qualifier word where a clause has
        # one, else the first the statement states.
        if qual:
            for clause, off in clauses(statement):
                if _overlap(qual, _tokens(clause), core):
                    hits = values(clause, kind, known_hosts=known_hosts, exclude=exclude, name_part=name_part)
                    if hits:
                        qpos = _token_positions(clause, qual, core)
                        spans = [(p, p + len(v)) for v, p in hits]
                        best_hit = min(hits, key=lambda h: (untyped(h[0]),
                                                            _rank(kind, clause, h[0], h[1], qpos, qual, spans)))
                        return best_hit[0], clause
        for clause, off in clauses(statement):
            hits = values(clause, kind, known_hosts=known_hosts, exclude=exclude, name_part=name_part)
            if kind == "count":
                hits = _count_near_noun(clause, qual, hits)
            if kind == "path":
                hits = sorted(hits, key=lambda h: (_shortcut(h[0]), h[1]))
            hits = sorted(hits, key=lambda h: untyped(h[0]))
            if hits:
                return hits[0][0], clause
        return None, ""
    if not qual:
        sentence, off = first_sentence_span(statement)
        hits = values(sentence, kind, known_hosts=known_hosts, exclude=exclude, name_part=name_part)
        if kind == "count":
            hits = _count_near_noun(sentence, set(), hits)
        if kind == "path":
            hits = sorted(hits, key=lambda h: (_shortcut(h[0]), h[1]))
        hits = sorted(hits, key=lambda h: untyped(h[0]))
        return (hits[0][0], sentence) if hits else (None, "")
    # A short qualifier must be carried whole ("initial activity" is not
    # "last activity"); a long one at least half.
    need = len(qual) if len(qual) <= 2 else (len(qual) + 1) // 2
    best: tuple | None = None   # (-overlap, nearness, value, clause)

    def consider(overlap: int, clause: str, hits: list[tuple[str, int]]) -> None:
        nonlocal best
        qpos = _token_positions(clause, qual, core)
        spans = [(p, p + len(v)) for v, p in hits]
        for v, p in hits:
            cand = (-overlap, (untyped(v), _rank(kind, clause, v, p, qpos, qual, spans)), v, clause)
            if best is None or cand[:2] < best[:2]:
                best = cand

    parts = clauses(statement)
    labels: list[tuple[int, str]] = []
    for i, (clause, off) in enumerate(parts):
        overlap = _overlap(qual, _tokens(clause), core)
        if overlap < need:
            continue
        hits = values(clause, kind, known_hosts=known_hosts, exclude=exclude, name_part=name_part)
        if kind == "count":
            hits = _count_near_noun(clause, qual, hits)
        if hits:
            consider(overlap, clause, hits)
        elif i + 1 < len(parts) and ":" in statement[off + len(clause):parts[i + 1][1]]:
            following = parts[i + 1][0]
            # A label that denies the value ("Install date not recorded:")
            # or a value clause that opens by denying it ("not recorded,
            # the account was created on ...") answers nothing.
            if _denies(clause) or _denies(following, opening=True):
                continue
            labels.append((overlap, statement[off:parts[i + 1][1] + len(following)]))
    if best is None:
        # "RegisteredOwner: Jane Roe": a label clause that names the part
        # without a value of the kind is answered by the clause after its
        # colon, the value nearest the label first. A value beside the
        # qualifier in its own clause is the stronger binding and is taken
        # before any label.
        for overlap, joined in labels:
            hits = values(joined, kind, known_hosts=known_hosts, exclude=exclude, name_part=name_part)
            if kind == "count":
                hits = _count_near_noun(joined, qual, hits)
            if hits:
                consider(overlap, joined, hits)
    return (best[2], best[3]) if best else (None, "")


_values = values
