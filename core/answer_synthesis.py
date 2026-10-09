"""Turn beliefs into an answer, and statements into headlines.

Two failures this fixes, both of the same shape — presenting raw internal
state where a reader expects a written conclusion.

**Questions were answered by concatenation.** The dashboard's answer was
the first two claim statements joined with a space. For a question about
data exfiltration that can produce an inventory of what had **not** been
looked at ("an absence hypothesis identified N unexamined evidence
categories …"), offered as the finding, while another question comes back
empty. Neither tells the reader what Atlas concluded.

**Findings had no headline.** Every finding was titled with its own full
statement, truncated mid-word, and then repeated that statement verbatim
under "Summary".

The fix is a separation the old code never made: a claim is *evidence of
something*, an answer is *a position on a question*, and a headline is
*neither* — it is a name. In particular, a statement about evidence nobody
examined is not an answer to anything, and this module refuses to let one
lead. Where the beliefs genuinely do not settle a question, that is stated
plainly, with the gap listed underneath — which is a real answer, and an
honest one.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

# Claim polarity. A belief either asserts something happened, asserts it did
# not, or reports that the evidence which would settle it was never read.
AFFIRMATIVE = "affirmative"
ABSENCE = "absence"
GAP = "gap"

_CONFIDENCE_RANK = {"CONFIRMED": 4, "LIKELY": 3, "SUSPECTED": 2,
                    "UNCONFIRMED": 1}

# "We never looked" language. These statements are investigative debt, not
# findings — the distinction a concatenated answer collapses. An examination
# verb carries it only negated after a modal ("could not be parsed") or in
# the perfect ("has not been reviewed"); an impact verb never does: "the
# document was not opened" is what happened, not what was left unread.
_GAP_RE = re.compile(
    r"(?i)\b("
    r"unexamined|(?:not|never)\s+(?:yet\s+)?(?:been\s+)?"
    r"(?:analy[sz]ed|reviewed|recovered|parsed|searched|examined|inspected)|"
    r"(?:could\s+not|couldn['’]t|can\s*not|can['’]t)\s+(?:yet\s+)?be\s+(?:fully\s+|reliably\s+)?"
    r"(?:determined|established|recovered|examined|analy[sz]ed|parsed|read|reviewed|searched|"
    r"processed|inspected|mounted|verified|assessed)|"
    r"remain(?:s|ing)?\s+(?:unexamined|open|unanalyzed)|"
    r"absence\s+hypothesis|further\s+examination|requires?\s+(?:further|"
    r"additional)\s+(?:analysis|examination|investigation)|"
    r"no\s+(?:direct\s+)?evidence\s+(?:was\s+)?(?:recovered|available)|"
    r"(?:analysis|examination|review|investigation|parsing|processing)\s+(?:\S+\s+){0,6}?pending|"
    r"pending\s+(?:further\s+)?(?:analysis|examination|review|investigation|parsing|processing)|"
    r"unavailable\s+for\s+(?:review|analysis)|"
    r"konnten?\s+(?:\S+\s+){0,4}?nicht\s+(?:\S+\s+){0,2}?(?:ermittelt|bestimmt|festgestellt|"
    r"wiederhergestellt|untersucht|ausgewertet|analysiert|gepr(?:ü|ue)ft|gelesen|verarbeitet|"
    r"eingebunden|gemountet|verifiziert)\s+werden|"
    r"(?:noch\s+)?nicht\s+(?:\S+\s+)?(?:untersucht|ausgewertet|analysiert|gepr(?:ü|ue)ft)|"
    r"(?:analyse|auswertung|untersuchung|pr(?:ü|ue)fung)\s+(?:\S+\s+){0,4}?(?:steht\s+(?:noch\s+)?aus|ausstehend)"
    r")\b"
)

# The examination itself in a lead ("The System hive was mounted"): a gap
# later in the sentence ("its ShimCache could not be parsed") is then what
# that examination left open, so the statement is a gap. Passive only: "the
# attacker mounted the share" is an act, not an examination; "scanned" is
# left out, a scan is as often the attacker's act as the analyst's.
_EXAMINED_LEAD_RE = re.compile(
    r"(?i)\b(?:was|were|is|are|been|wurden?|ist|sind)\b(?:\s+\S+){0,3}?\s+"
    r"(?:mounted|examined|checked|parsed|reviewed|searched|analy[sz]ed|inspected|processed|"
    r"eingebunden|gemountet|untersucht|gepr(?:ü|ue)ft|ausgewertet|analysiert|durchsucht|"
    r"verarbeitet)\b")

# "It is not there" language — a real negative finding, distinct from a gap.
_ABSENCE_RE = re.compile(
    r"(?i)\b(?:no|none|never|not|nicht|kein[es]?|nie)\b(?:\s+\S+){0,6}?\s*"
    r"(?:found|present|observed|identified|detected|recorded|seen|exist(?:s|ed)?|"
    r"gefunden|vorhanden|beobachtet|festgestellt|aufgezeichnet)"
    r"|\b(?:absent|absence of|missing|not present|no such|no indication|no evidence of|"
    r"rules? out|excludes?|contain(?:s|ed)? only|shows? no|does not exist|"
    r"were not recovered|was not recovered|lack of|zero (?:hits|matches|results)|"
    r"0 (?:hits|matches|results)|fehlt|fehlen|abwesend)\b")

# A clause ending on one of these is still mid-sentence — cutting a headline
# there leaves "The MFT timeline shows." Keep reading to a real boundary.
_DANGLING_TAIL_RE = re.compile(
    r"(?i)\b(shows?|showed|indicates?|includes?|reveals?|found|contains?|"
    r"identified|lists?|reports?|records?)$")

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
# A full stop that closes a title, an initial or a common abbreviation is not
# the end of a sentence: "Mr. Evil", "J. Smith", "approx. 5 files".
_ABBREVIATION_TAIL_RE = re.compile(
    r"(?:^|[\s(\[\"'\u201c\u2018\\/])(?:Mr|Mrs|Ms|Dr|Prof|Sr|Jr|St|Mt|No|Nr|vs|approx|ca|etc|"
    r"Inc|Ltd|Co|Corp|Fig|Vol|Hr|Fr|bzw|z\.B|u\.a|e\.g|i\.e|[A-Z])\.$")


def first_sentence(text: str) -> str:
    """The first sentence of ``text``, whitespace-normalised. A stop after
    an abbreviation or an initial, or one followed by a lower-case word, is
    inside the sentence, not its end."""
    body = " ".join(str(text or "").split())
    for m in _SENTENCE_END.finditer(body):
        head = body[:m.start()]
        nxt = body[m.end():m.end() + 1]
        if nxt and nxt.islower():
            continue
        if _ABBREVIATION_TAIL_RE.search(head):
            continue
        return head
    return body
_HEADLINE_TRIM = re.compile(
    r"(?i)^(?:the\s+|a\s+|an\s+|it\s+(?:was|is)\s+|analysis\s+(?:shows|"
    r"indicates)\s+that\s+|evidence\s+(?:shows|indicates)\s+that\s+)")

MAX_HEADLINE = 96


def classify_statement(statement: str) -> str:
    """Whether a belief asserts a fact, asserts an absence, or reports a gap."""
    text = str(statement or "")
    # The first sentence carries the assertion; "Ransomware on the file
    # server. No encrypted files on the DC." is a positive finding with a
    # scoping clause, not an absence claim. A gap is read in its lead clause
    # (up to "; "): "Encryption of the share began ...; the ransom note could
    # not be recovered" asserts the encryption, its caveat is no gap. When
    # the lead reports an examination, a gap later in the sentence is what
    # that examination left open; when it reports an absence ("No evidence
    # of exfiltration was found; the proxy logs were not examined"), the gap
    # leaves the absence unsettled, and a gap it stays.
    first = first_sentence(text)
    lead = first.split("; ", 1)[0]
    if _GAP_RE.search(lead) or (_GAP_RE.search(first) and (_EXAMINED_LEAD_RE.search(lead)
                                                           or _ABSENCE_RE.search(lead))):
        return GAP
    if _ABSENCE_RE.search(first):
        return ABSENCE
    return AFFIRMATIVE


_TECH_TAIL_RE = re.compile(
    r"\s*(?:\((?:Security\s+)?(?:EID|Event\s*ID|event)\s*\d{3,5}[^)]*\)|"
    r"[—–-]\s*(?:Security\s+)?(?:EID|event(?:\s+id)?)\s*\d{3,5}\b[^.;]*|"
    r",?\s*(?:Account\s+)?SID:?\s*S-1-5-21(?:-\d+){3,4}|"
    r"\s*\((?:inode|RecordNumber|record)\s*[^)]*\))", re.I)


_IDENT_PAREN_RE = re.compile(
    r"\s*\((?=[^)]*(?:\b[0-9a-f]{32,64}\b|\bSHA-?\d|\bMD5\b|\bv\d+\.\d|\b\d[\d,]* ?bytes\b|\bEID\b|"
    r"\bevent\s*id|\bS-1-5-|\binode\b|\bRecordNumber\b|\bLogonType\b|\bType \d\b|\bversion\b))[^)]*\)", re.I)


_OPEN_QUOTE_RE = re.compile(r"(?:^|[\s(\[])[\"'“‘`](?=\S)")
_CLOSE_QUOTE_RE = re.compile(r"(?<=\S)[\"'”’`](?=$|[\s.,;:)\]])")


def _unclosed_quote_start(text: str) -> int:
    """Index of the last opening quotation mark that is never closed, or -1."""
    pos = 0
    while True:
        m = _OPEN_QUOTE_RE.search(text, pos)
        if not m:
            return -1
        c = _CLOSE_QUOTE_RE.search(text, m.end())
        if not c:
            return m.start()
        pos = c.end()


# A lone separator a cut can leave at the end ("... USER jdoe /"):
# typography, not content.
_TRAILING_SEPARATOR_RE = re.compile(r"\s*[/|\\=+\-–—:]+$")


def _terminate(point: str) -> str:
    """An answer sentence's end: a shortened point keeps its ellipsis, so a
    fragment never reads as a finished sentence; any other ends in a stop."""
    return point if point.endswith("…") else point.rstrip(".") + "."


def _plain_headline(statement: str, *, limit: int = 120) -> str:
    """A headline as an answer reads it: no event ids, hashes, sizes, record
    numbers or SIDs — those stay in the finding the answer cites. A point
    that had to be cut (at the length, back to a clause boundary, before an
    unclosed parenthesis or quotation) ends in "…": the cited finding holds
    the rest, and the reader must not take the fragment for the whole."""
    text = _IDENT_PAREN_RE.sub("", " ".join(str(statement or "").split()))
    h = headline(text, limit=limit, label_only=False)
    cut = h.endswith("…")
    keep_paren = False
    h = _TECH_TAIL_RE.sub("", h)
    if "; " in h:
        h = h.split("; ", 1)[0]           # one clause is the headline
    if h.endswith("…"):
        core = h.rstrip("…")
        for sep in (" — ", "; ", ", ", " at ", " from ", " with "):
            k = core.rfind(sep)
            if k >= int(len(core) * 0.5):
                core = core[:k]
                break
        h = core
    # a cut may leave a dangling connector ("… by jane.doe at")
    h = re.sub(r"\s+(?:at|from|to|by|in|on|with|and|or|of|via|for|into|onto|under|the|a|an)$", "", h.rstrip("…").strip())
    if h.count("(") > h.count(")"):
        cut = True
        if len(h[:h.rfind("(")].split()) >= 3:
            h = h[:h.rfind("(")]          # a cut inside a parenthetical
        else:
            # One or two words before it are a label ("Staging (the copy
            # to the key ..."): the parenthetical is the point, kept and
            # closed where the cut fell.
            keep_paren = True
    q = _unclosed_quote_start(h)
    if q >= 0:
        h = h[:q]                         # a cut inside a quotation
        cut = True
    h = " ".join(h.split()).strip(" ,;—–-").rstrip(".")
    if cut:
        h = _TRAILING_SEPARATOR_RE.sub("", h).strip(" ,;")
    if keep_paren and h.count("(") > h.count(")"):
        k = h.rfind("(")
        if h[k + 1:].strip():
            return h + "…)"               # already marked as cut: no second ellipsis
        h = h[:k].rstrip()
    return h + "…" if cut and h else h


def headline(statement: str, *, limit: int = MAX_HEADLINE, label_only: bool = True) -> str:
    """A short name for a finding — not its full text.

    Takes the first clause, drops throat-clearing openers, and cuts on a
    word boundary. Deterministic: the same statement always names the same
    finding, so headings stay stable across report regenerations.
    ``label_only=False`` is for text that stands for what the finding says
    (an answer point, a gap listed under an answer, a list of held findings):
    a long "label: facts" lead is then never reduced to its label.
    """
    body = " ".join(str(statement or "").split())
    if not body:
        return ""
    first = first_sentence(body).strip()
    first = _HEADLINE_TRIM.sub("", first).strip()
    # A leading "<subject>:" list intro reads better cut at the colon —
    # unless that leaves a dangling verb ("…MFT timeline shows").
    # Only a colon followed by whitespace introduces a list; the ones in
    # "D:\Finance" and "11:15:20" cut headings at "copy D" and "at 11".
    m = re.search(r":\s", first[:limit])
    if m and len(first) > limit:
        head = first[:m.start()].strip()
        tail = first[m.end():].strip()
        # "Topic: the facts": the facts side is the headline when it names
        # what the label side does not (a value, an address, a file, a
        # time); a label that is itself a citation keeps nothing the tail
        # lacks only when the tail adds no entity of its own.
        try:
            from core.entities import discriminative, extract
            tail_only = discriminative(extract(tail)) - discriminative(extract(head))
        except Exception:  # noqa: BLE001 - the label rule stands without the extractor
            tail_only = set()
        if tail_only and tail:
            first = tail[:1].upper() + tail[1:]
            if len(first) <= limit:
                return first.rstrip(".")
        elif (label_only and 20 <= len(head) <= limit and not _DANGLING_TAIL_RE.search(head)
                and _unclosed_quote_start(head) < 0):
            return head
    if len(first) <= limit:
        return first.rstrip(".")
    cut = first[:limit].rsplit(" ", 1)[0].rstrip(",;:")
    # A clause boundary well inside the limit reads better than a word cut.
    for sep in (" — ", "; ", " - "):
        at = first[:limit].rfind(sep)
        if at >= int(limit * 0.55):
            cut = first[:at].rstrip(",;:")
            break
    q = _unclosed_quote_start(cut)
    if q > 0:
        cut = cut[:q].rstrip(",;:")       # never end inside a quotation
    while cut and _DANGLING_TAIL_RE.search(cut):
        cut = cut.rsplit(" ", 1)[0].rstrip(",;:") if " " in cut else ""
    return (cut + "…") if cut else first[:limit].rstrip() + "…"


def _rank(node: dict) -> int:
    return _CONFIDENCE_RANK.get(str(node.get("confidence") or "").upper(), 0)


def _hosts_in(nodes: Iterable[dict]) -> list[str]:
    out: list[str] = []
    for n in nodes:
        h = str(n.get("host") or "").strip()
        if h.lower() in ("estate", "case", "all", "multiple", "unknown", "n/a", "-", "—"):
            continue                      # a scope word, not a machine
        if h and h not in out:
            out.append(h)
    return out


def _timespan(nodes: Iterable[dict]) -> str:
    """Earliest → latest timestamp mentioned across the supporting beliefs."""
    from core.forensic_citation import normalize_timestamp
    stamps: list[str] = []
    for n in nodes:
        for ev in (n.get("evidence") or []):
            if isinstance(ev, dict):
                ts = normalize_timestamp(ev.get("timestamp"))
                if ts:
                    stamps.append(ts)
        ts = normalize_timestamp(n.get("statement"))
        if ts:
            stamps.append(ts)
    if not stamps:
        return ""
    lo, hi = min(stamps), max(stamps)
    return lo if lo == hi else f"{lo} → {hi}"


# A question that opens with an auxiliary verb wants "yes" or "no" first —
# grammar (English and German), not knowledge about any case.
_YES_NO_RES = {
    "en": re.compile(r"(?i)^(?:was|were|is|are|did|do|does|has|have|had|can|could)\b"),
    # "Was" is German for "what" — never a yes/no opener there.
    "de": re.compile(r"(?i)^(?:wurde|wurden|ist|sind|war|waren|gab|gibt|hat|haben|hatte|kann|konnte|können)\b"),
}
_YES_NO_WORDS = {"en": ("Yes", "No"), "de": ("Ja", "Nein")}


def _is_yes_no(question: str, language: str = "en") -> bool:
    rx = _YES_NO_RES.get((language or "en")[:2].lower(), _YES_NO_RES["en"])
    return bool(rx.match(question or ""))


# The shape of answer a question wants beyond yes or no: a number, a set
# of named items, a person, a time, or an account of what happened. A
# count answered without a number, or "which files" answered with
# "several images", is an answer in words only.
_COUNT_Q_RE = re.compile(
    r"(?i)\b(?:how many|how much|how often|number of|count of|total (?:number|count)(?: of)?|"
    r"wie ?viele|wieviel|wie oft|anzahl|gesamtzahl)\b")
_WHO_Q_RE = re.compile(r"(?i)^(?:who|whom|whose|wer|wem|wen|wessen)\b|\b(?:by whom|von wem)\b")
_WHEN_Q_RE = re.compile(
    r"(?i)^(?:when|wann)\b|\b(?:what time|which date|what date|which day|zeitpunkt|zeitraum|"
    r"welches datum|um wie ?viel uhr|wie spät)\b")
_ENUM_Q_RE = re.compile(
    r"(?i)^(?:which|welche[rs]?|list|enumerate|name|identify|liste|nenne|zähle)\b|"
    r"\b(?:all (?:of )?the|alle|recover(?:ed)?|extract(?:ed)?|wiederherstell)")
# Things whose members carry an extractable name (a file name, an address,
# a hash): for these a description without a name is short of an answer.
_NAMEABLE_WORDS = (
    r"(?:files?|images?|pictures?|photos?|documents?|archives?|videos?|artifacts?|artefacts?|"
    r"dateien?|bilder|fotos?|dokumente?|archive|hashes|ips?|addresses|adressen|domains?|urls?|"
    r"hosts?|hostnames?|e-?mails?|mails?)")
# The asked-for thing stands at the front of a question ("which files",
# "what images did"); a host or file named further on is where, not what.
_NAMEABLE_LEAD_RE = re.compile(r"(?i)^(?:\w+\s+){0,3}" + _NAMEABLE_WORDS + r"\b")
_NUMBER_WORD_RE = re.compile(
    r"(?i)\b(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|none|no|zero|"
    r"ein|eine|einen|zwei|drei|vier|fünf|sechs|sieben|acht|neun|zehn|elf|zwölf|keine?|null)\b")
_SERIES_RE = re.compile(r":\s*[^,;]+(?:[,;]\s*[^,;]+)+")


# A request often opens with a label ("Malware — whether the machine
# carries viruses", "Baseline: both operating systems"): the body after the
# label is what asks, and what the kind, the umbrella test and the answer
# read. A label is at most eight words before an em dash, an en dash or a
# colon followed by a space.
_LEAD_LABEL_RE = re.compile(r"^\s*(?:\*\*)?([^—–:\n]{1,60}?)(?:\*\*)?\s*(?:—|–|:)\s+(?=\S)")
_WHETHER_RE = re.compile(r"(?i)^(?:whether|ob|any)\b")
# A label is a topic, never a question: text before a colon that ends in a
# question mark or opens with a question word or a yes/no auxiliary
# ("Is there evidence of lateral movement: yes or no?") is the request.
_QUESTION_OPENER_RE = re.compile(
    r"(?i)^(?:what|which|who|whom|whose|when|where|why|how|whether|any|is|are|was|were|did|do|"
    r"does|has|have|had|can|could|should|will|would|welche[rs]?|wer|wen|wem|wessen|wann|wo|wie|"
    r"warum|ob|ist|sind|war|waren|wurde|wurden|gab|gibt|hat|haben|hatte|kann|konnte|können|"
    r"sollte)\b")


def _is_label(text: str, sep: str = ":") -> bool:
    """A topic before a dash is a label whatever its words ("Who used it —
    main and last user"); before a colon it is a label unless it is
    itself a question."""
    label = text.strip()
    if not label or len(label.split()) > 8:
        return False
    if sep != ":":
        return True
    return not label.endswith("?") and not _QUESTION_OPENER_RE.match(label)


def request_body(text: str) -> str:
    """The request after its lead label, or the request itself."""
    body = " ".join(str(text or "").split())
    m = _LEAD_LABEL_RE.match(body)
    if m and _is_label(m.group(1), body[m.end() - 2:m.end()].strip()[:1] if m.end() >= 2 else ":"):
        return body[m.end():].strip()
    return body


def question_kind(question: str, language: str = "en") -> str:
    """``yes_no``, ``count``, ``who``, ``when``, ``enumeration`` or ``what``:
    the shape of answer the question asks for, read from the request's body
    after its lead label."""
    q = request_body(question)
    if _is_yes_no(q, language) or _WHETHER_RE.match(q):
        return "yes_no"
    if _COUNT_Q_RE.search(q):
        return "count"
    if _WHO_Q_RE.search(q):
        return "who"
    if _WHEN_Q_RE.search(q):
        return "when"
    if _ENUM_Q_RE.search(q) or (re.match(r"(?i)^what\b", q) and _NAMEABLE_LEAD_RE.match(q)):
        return "enumeration"
    return "what"


def answer_shape_gap(question: str, statements: Iterable[str], language: str = "en") -> str:
    """How the statements fall short of the shape the question asks for:
    ``"count"`` when a count question gets no number, ``"named"`` when a
    question about nameable things gets nothing named, ``""`` otherwise.
    Advisory: the answer stands either way."""
    text = " ".join(s for s in statements if s).strip()
    if not text:
        return ""
    kind = question_kind(question, language)
    if kind == "count":
        return "" if _NUMBER_WORD_RE.search(text) else "count"
    if kind == "enumeration" and _NAMEABLE_LEAD_RE.match(question or ""):
        from core.entities import artifact_tokens, discriminative, extract
        named = artifact_tokens(text) or discriminative(extract(text)) or _SERIES_RE.search(text)
        return "" if named else "named"
    return ""


# What a question asks about, and the words a belief uses when it answers
# that: (question stems, answer vocabulary). The stem that occurs earliest in
# the question is its subject ("which accounts were compromised" asks about
# accounts, not about the compromise).
_INTENTS: tuple[tuple[re.Pattern, re.Pattern], ...] = tuple(
    (re.compile(q, re.I), re.compile(a, re.I)) for q, a in (
        (r"\battack(?!er)|\bangriff|incident|vorfall|compromis|kompromitt|suspicious|verdächtig|malicious|bösartig|anomal|\bthreat|bedroh|intrusion|einbruch|what (kind|type)|welche art|malware|schadsoftware|\bvir(?:us|en)\b|trojan|infect|infiz",
         r"ransomware|malware|encrypt|verschlüssel|phish|exploit|brute.?force|intrusion|backdoor|beacon|\bc2\b|webshell|trojan|dropper|payload|extortion|erpress|attacker|angreifer|adversar|compromis|kompromitt|infect|infiz|malicious|bösartig|suspicious|verdächtig|threat actor|unauthori[sz]ed|unbefugt|\bvirus|\bviren|antivirus|anti-virus|\bav\b|clamav|defender|quarantin|signature|hacktool|riskware|\bpua\b|schadsoftware"),
        (r"account|\bkont[oe]n?\b|\buser|benutzer|nutzer|credential|anmeldedaten|password|passwort|identit|\bwho\b|\bwer\b|logon|login|anmeld",
         r"account|konto|\buser|benutzer|nutzer|logon|login|anmeld|credential|password|passwort|\brdp\b|created|angelegt|erstellt|added|hinzugef|group|gruppe|admin|privilege|berechtig|rechte|impersonat|kerberos|ntlm"),
        (r"initial access|entry point|einstieg|eingedrungen|\bget in\b|gelangt|zugang|zugriff|\baccess|vector|vektor|how did|wie (kam|kamen|gelang|konnte)",
         r"logon|login|anmeld|\bvpn\b|\brdp\b|phish|exploit|vulnerab|schwachstelle|public.facing|\bssh\b|initial access|foothold|remote access|external|extern|internet.facing|\baccess"),
        (r"lateral|seitwärts|spread|ausbreit|\bmoved\b|bewegt|pivot|between (hosts|systems)|other (hosts|systems)|weitere (systeme|hosts|rechner)|propagat",
         r"\brdp\b|\bsmb\b|psexec|\bwmi\b|winrm|logon type|remote|lateral|moved|bewegt|pivot|admin\$|c\$|net use|pass.the|mstsc|terminalservices|type 10|type 3"),
        (r"persist|foothold|remain|verbleib|dauerhaft|survive|reboot|neustart|backdoor|hintertür",
         r"scheduled task|schtasks|aufgabenplan|geplante aufgabe|service|dienst|run key|runonce|autorun|startup|autostart|\bwmi\b|subscription|created|angelegt|persist|backdoor|hintertür|registry"),
        (r"exfil|stolen|gestohlen|entwendet|\bleak|abfluss|abgeflossen|\bdata\b|daten|extortion|erpress|upload|hochgeladen|left the",
         r"exfil|upload|hochgeladen|transfer|übertrag|outbound|ausgehend|rclone|mega|\bftp\b|sftp|archive|archiv|\.7z|\.zip|\.rar|double.extortion|leak|stolen|gestohlen|entwendet|cloud|dropbox|onedrive|gigabyte|\bgb\b|\bmb\b"),
        (r"\bwhen\b|\bwann\b|timeline|zeitlich|zeitraum|\bfirst\b|\berste[nr]?\b|\blast\b|\bletzte[nr]?\b|how long|wie lange|dwell|\bdate\b|datum|\btime\b|\bzeit|duration|dauer|\bstart|\bbegin|beginn|\bend\b",
         r"\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}|\butc\b|between|zwischen|\bfirst|\berst|\blast|\bletzt|until|\bbis\b|since|\bseit\b|before|\bvor\b|after|\bnach\b|\bam \d|\bon \d"),
        (r"firewall|network|netzwerk|\bvpn\b|proxy|\bdns\b|connection|verbindung|traffic|verkehr|\bip\b|remote|\bc2\b|beacon|external|extern|internet|outbound|inbound",
         r"firewall|\bvpn\b|gateway|proxy|\bdns\b|connection|verbindung|traffic|verkehr|\bdeny|\bdrop|\ballow|accept|outbound|ausgehend|inbound|eingehend|\bport\b|session|tunnel|\d{1,3}(?:\.\d{1,3}){3}|beacon|\bc2\b|http"),
        (r"malware|schadsoftware|\btool|binary|binär|executable|script|skript|\bfile|datei|program|dropped|abgelegt|payload|\bhash|sample",
         r"\.exe\b|\.dll\b|\.ps1\b|\.bat\b|\.vbs\b|\.js\b|\.jar\b|powershell|cmd\.exe|executed|ausgeführt|\bran\b|dropped|abgelegt|binary|binär|script|skript|payload|\bhash|sha256|sha1|md5|malware|schadsoftware|ransomware|encrypt|verschlüssel|\btool"),
        (r"which (hosts|systems|machines|servers|devices)|welche (hosts|systeme|rechner|server|geräte)|affected|betroffen|impact|auswirk|ausmaß|how many|wie viele|scope|umfang|encrypted|verschlüsselt|damage|schaden",
         r"\bhost|system|machine|rechner|server|workstation|affected|betroffen|encrypted|verschlüsselt|\bfiles\b|dateien|estate|domain"),
        (r"log clear|logs? (were|was) (cleared|deleted|wiped)|anti.?forensic|cover|tracks|spuren|gelöscht|deleted|wiped|tamper|manipul|evasion|defense",
         r"cleared|\bclear|1102|\b104\b|wevtutil|deleted|gelöscht|wiped|anti.?forensic|tamper|manipul|evasion|disabled|deaktiviert|defender|\bav\b|antivirus|sdelete|cipher"),
    ))


def question_subject(question: str) -> int | None:
    """Index into ``_INTENTS`` of what the question asks about — the intent
    whose stem appears earliest — or None when no stem matches."""
    best: tuple[int, int] | None = None
    for i, (q_re, _) in enumerate(_INTENTS):
        m = q_re.search(question or "")
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), i)
    return None if best is None else best[1]


def speaks_to(question: str, statement: str, host: str = "", *,
              strict: bool = False) -> bool:
    """Does a belief speak to the question?

    Yes when they share content words (the question's account, host, address
    or file), when the question is an umbrella one, or when the belief uses
    the vocabulary of what the question asks about — "what type of attack"
    is answered by a ransomware claim although no word is shared. A question
    with no recognisable subject cannot be judged: a gate lets it through
    (``strict=False``), an answer must not be invented for it (``strict``).
    """
    try:
        from core.forensic_citation import host_name_forms
        from core.investigation_tasks import link_tokens
        stmt_toks = link_tokens(statement) | link_tokens(host) | set(host_name_forms(host))
        if link_tokens(question) & stmt_toks:
            return True
    except Exception:  # noqa: BLE001
        pass
    if is_general_question(question):
        return True
    subject = question_subject(question)
    if subject is None:
        return not strict
    return bool(_INTENTS[subject][1].search(f"{statement} {host}"))


def _relevance(question: str, statement: str) -> int:
    """How much a belief is about the question, by shared content words —
    so "was an account created?" is answered by the account claim before
    the Amcache inventory it happens to share a host with."""
    try:
        from core.investigation_tasks import link_tokens
        return len(link_tokens(question) & link_tokens(statement))
    except Exception:  # noqa: BLE001
        return 0


# The act a question asks about and the words a finding uses for the same
# act, across the report languages. A finding that names the act answers
# the question directly; one that only shares its subject is an indication.
_ACT_GROUPS = tuple(re.compile(rx, re.I) for rx in (
    r"\b(?:creat|angelegt|erstell|added|hinzugef|eingerichtet)",
    r"\b(?:delet|gelöscht|removed|entfernt|wiped)",
    r"\b(?:encrypt|verschlüssel|ransom)",
    r"\b(?:exfil|stolen|gestohlen|entwendet|upload|hochgeladen|transferr|übertrag|leak|abgeflossen)",
    r"\b(?:log(?:ged)?\s*(?:on|in)|logon|login|anmeld|authenticat|authentifiz)",
    r"\b(?:execut|ausgeführt|\bran\b|launch|gestartet)",
    r"\b(?:download|heruntergeladen|staged|abgelegt|dropped)",
    r"\b(?:install|installiert|persist|scheduled task|dienst|service)",
    r"\b(?:clear(?:ed)?|gelöscht|wevtutil|1102|tamper|manipul)",
    r"\b(?:lateral|seitwärts|moved|pivot|rdp|smb|psexec|winrm)",
    r"\b(?:compromis|kompromitt|breach|intrusion|einbruch|attack(?!er)|angriff)",
))


# What a "what type of attack" question wants named: the kind of incident,
# not the actor or a tool.
_INCIDENT_TYPE_RE = re.compile(
    r"(?i)ransomware|encrypt|verschlüssel|extortion|erpress|wiper|malware|phish|insider|"
    r"data theft|datendiebstahl|defacement|denial.of.service|business email|\bbec\b|"
    r"verschlüsselungstrojaner|supply.chain|account takeover")
_TYPE_WORDS_RE = re.compile(
    r"(?i)brute.?force|exploit|backdoor|webshell|trojan|\bc2\b|lateral movement|"
    r"credential (?:theft|dump)|persistence|privilege escalation")


def lead_sentence(text: str) -> str:
    """The first sentence: the assertion a statement makes, before its
    scoping and caveats."""
    first = first_sentence(text)
    return first.split("; ", 1)[0]


def _shares_act(question: str, statement: str) -> bool:
    return any(rx.search(question or "") and rx.search(statement or "") for rx in _ACT_GROUPS)


# A request that asks for a relation ("prove the connection between X and
# Y", "link X to Y") is answered only by a finding that states one: a
# relation word in its lead sentence and a term from each side. A transfer
# within one source ("copied to", "sent to") is a relation word too, but
# without both sides named it describes one source.
_RELATION_REQUEST_RE = re.compile(
    r"(?i)\b(?:prove|link|connect|correlat\w*|relat\w*|match|tie|belege?n?|verknüpf\w*|"
    r"verbind\w*|korrelier\w*|zusammenhang|verbindung|connection)\b")
_RELATION_SIDES_RES = (
    re.compile(r"(?i)\bbetween\s+(.+?)\s+and\s+(.+)"),
    re.compile(r"(?i)\bzwischen\s+(.+?)\s+und\s+(.+)"),
    re.compile(r"(?i)\b(?:link|connect|correlate|relate|match|tie|verknüpfe?n?|verbinde?n?)\s+(.+?)\s+(?:to|with|and|mit|zu|und)\s+(.+)"),
)
_RELATION_WORD_RE = re.compile(
    r"(?i)\b(?:identical|same|match(?:es|ed|ing)?|linked|links|connect(?:s|ed|ion)?|"
    r"correlat\w*|corresponds?|derived from|copied|transferred|sent to|uploaded to|"
    r"downloaded from|originat\w*|derselbe|dieselbe|dasselbe|identisch|gleich\w*|"
    r"verknüpft|verbunden|übertragen|kopiert|stammt)\b")


def _relation_sides(question: str) -> tuple[set[str], set[str]] | None:
    """The two sides a relational request names, as content-word sets, or
    None when the request asks for no relation or names no two sides."""
    body = request_body(question)
    if not _RELATION_REQUEST_RE.search(body):
        return None
    try:
        from core.investigation_tasks import link_tokens
    except Exception:  # noqa: BLE001
        return None
    for rx in _RELATION_SIDES_RES:
        m = rx.search(body)
        if m:
            left, right = link_tokens(m.group(1)), link_tokens(m.group(2).rstrip(".?"))
            if left and right:
                return left, right
    return None


def _relates(lead: str, sides: tuple[set[str], set[str]]) -> bool:
    """A lead sentence states the relation the request asks for: it carries
    a relation word and names a term from each side."""
    if not _RELATION_WORD_RE.search(lead or ""):
        return False
    try:
        from core.investigation_tasks import link_tokens
    except Exception:  # noqa: BLE001
        return False
    toks = link_tokens(lead)
    return bool(toks & sides[0]) and bool(toks & sides[1])


# The share of content words that makes one answer point another's
# restatement: the record-time guard's default, fixed here so switching that
# guard off (ATLAS_FINDING_NEAR_DUPLICATE_MIN=off) does not change answers.
_ANSWER_FOLD_SHARE = 0.7


def _host_names(text: str) -> set[str]:
    return {m.group(0).lower() for m in _HOSTLIKE_RE.finditer(text or "")}


# The preposition a machine takes in an answer's own language.
_ON_HOST = {"en": "on", "de": "auf"}


def _tell_hosts_apart(points: list[str], nodes: list[dict], on: str = "on") -> list[str]:
    """Points that read alike word for word name their host, so an answer
    about two hosts does not print one line twice. A point that already
    names its host stays as it is."""
    seen: dict[str, int] = {}
    for p in points:
        seen[p.lower()] = seen.get(p.lower(), 0) + 1
    out = []
    for p, n in zip(points, nodes):
        host = str(n.get("host") or "").strip()
        if seen[p.lower()] > 1 and host and host.lower() not in p.lower():
            p = f"{p} {on} {host}"
        out.append(p)
    return out


def _adds_only_time(new: str, old: str) -> bool:
    """``new`` adds to ``old`` nothing but times and numbers: the same kind
    of event again, at another moment."""
    from core import entities as _ent
    added = {e for e in _ent.discriminative(_ent.extract(new)) - _ent.discriminative(_ent.extract(old))
             if not e.startswith("ts:")}
    return not added and not (_ent.domains_in(new) - _ent.domains_in(old))


def _restates_kept(node: dict, kept: list[dict], *, diversity: bool = False) -> bool:
    """Whether answer point ``node`` says nothing a kept point on the same
    host does not: the same headline, or a restatement or a rewording at
    more length (core.entities.relation, the record-time guard's rule, at
    its default share; a refinement adds an entity or a number and is a
    different fact). A point naming a host-shaped name the kept point does
    not is never folded, since the relation reads no host as an entity and
    "to CORP-DC01" would restate "to CORP-FS01" (ceiling: a host name
    without the hyphen-and-digit shape). ``diversity`` also folds a
    refinement that adds only times and numbers, for an overview that has
    more candidates than points. The same headline on another host is kept
    and told apart by its host (``_tell_hosts_apart``).
    """
    from core.entities import relation
    stmt = str(node.get("statement") or "")
    head = _plain_headline(stmt).lower()
    host = " ".join(str(node.get("host") or "").split()).lower()
    for k in kept:
        if host != " ".join(str(k.get("host") or "").split()).lower():
            continue
        kstmt = str(k.get("statement") or "")
        if head and head == _plain_headline(kstmt).lower():
            return True
        if _host_names(stmt) - _host_names(kstmt):
            continue
        rel = relation(stmt, kstmt, threshold=_ANSWER_FOLD_SHARE, elaborates=True)
        if rel and (rel[0] in ("restates", "elaborates")
                    or (diversity and rel[0] == "refines" and _adds_only_time(stmt, kstmt))):
            return True
    return False


def synthesize_answer(
    question: str,
    claims: Iterable[dict],
    *,
    max_points: int = 3,
    language: str = "en",
    chronological: bool = False,
) -> dict[str, Any]:
    """Answer ``question`` from its supporting beliefs.

    Returns ``{"verdict", "text", "points", "gaps", "confidence",
    "hosts", "timespan", "counts"}``. The verdict states the position;
    ``text`` is a written answer; gaps are listed separately so unexamined
    evidence can never be mistaken for a conclusion.
    """
    nodes = [n for n in claims if isinstance(n, dict)]
    active = [n for n in nodes
              if str(n.get("status") or "") not in ("superseded", "withdrawn")]

    buckets: dict[str, list[dict]] = {AFFIRMATIVE: [], ABSENCE: [], GAP: []}
    for n in active:
        buckets[classify_statement(n.get("statement") or "")].append(n)

    for key in buckets:
        buckets[key].sort(
            key=lambda n: (_relevance(question, n.get("statement") or ""), _rank(n)),
            reverse=True)

    positive = buckets[AFFIRMATIVE]
    negative = buckets[ABSENCE]
    gaps = buckets[GAP]

    best_rank = max((_rank(n) for n in positive), default=0)
    confidence = next(
        (name for name, r in _CONFIDENCE_RANK.items() if r == best_rank), None)

    hosts = _hosts_in(positive or negative)
    span = _timespan(positive or negative)

    if positive:
        verdict = ("Indicators found"
                   if best_rank >= _CONFIDENCE_RANK["SUSPECTED"]
                   else "Possible indicators, weakly supported")
    elif negative:
        verdict = "No supporting evidence found"
    elif gaps:
        verdict = "Not established — required evidence was never examined"
    else:
        verdict = "Not answered"

    # The written answer is an answer, not a quotation: one lead sentence
    # that states the position in the question's own terms, then at most a
    # couple of short supporting headlines, then — separately and last —
    # what was not read. Full statements, event ids and record numbers stay
    # in the findings the answer cites.
    sentences: list[str] = []
    lang = (language or "en")[:2].lower()
    yes, no = _YES_NO_WORDS.get(lang, _YES_NO_WORDS["en"])

    def _addresses(n: dict) -> bool:
        stmt = str(n.get("statement") or "")
        return _relevance(question, stmt) > 0 or speaks_to(
            question, stmt, str(n.get("host") or ""), strict=True)

    # Only findings that address the question may carry a Yes or a No; the
    # strongest unrelated finding is context, never the answer.
    rel_pos = [n for n in positive if _addresses(n)]
    rel_neg = [n for n in negative if _addresses(n)]
    def _lead_sentence(text: str) -> str:
        return first_sentence(text)

    question_has_act = any(rx.search(question or "") for rx in _ACT_GROUPS)
    subject = question_subject(question)
    subject_re = _INTENTS[subject][1] if subject is not None else None
    type_question = bool(re.search(r"(?i)\bwhat (?:type|kind)|welche art|art (?:des|von)", question or ""))
    kind = question_kind(question, language)
    relation_sides = _relation_sides(question)

    def _direct(n: dict) -> bool:
        # The finding's lead sentence names the act the question asks about
        # (in either language), or it is the analyst's own conclusion. A
        # later sentence that merely mentions the word ("cannot support
        # exfiltration analysis") is not an answer. For questions that name
        # no act, sharing the question's own words is enough. A request for
        # a relation is answered only by a stated relation, conclusions
        # included.
        lead_s = _lead_sentence(n.get("statement"))
        if relation_sides is not None:
            return _relates(lead_s, relation_sides)
        if n.get("kind") == "conclusion" or _shares_act(question, lead_s):
            return True
        return not question_has_act and _relevance(question, lead_s) > 0

    def _order(n: dict) -> tuple:
        # Best answer first. For "what type of attack": the kind of incident
        # (ransomware, phishing…) before a technique (lateral movement, C2),
        # then a direct answer, the subject's vocabulary, tier, word overlap.
        stmt = str(n.get("statement") or "")
        lead_s = _lead_sentence(stmt)
        vocab = bool(subject_re and subject_re.search(stmt))
        if type_question:
            return (bool(_INCIDENT_TYPE_RE.search(lead_s)), bool(_TYPE_WORDS_RE.search(lead_s)),
                    _direct(n), vocab, _rank(n), _relevance(question, lead_s))
        return (_direct(n), vocab, _rank(n), _relevance(question, lead_s))

    rel_pos.sort(key=_order, reverse=True)
    rel_neg.sort(key=_order, reverse=True)
    pool = list(rel_pos or rel_neg or positive or negative)
    if chronological:
        pool = list(positive or negative)
        pool = sorted(pool, key=lambda n: (_when(n) or "~", n.get("id") or ""))
    heads = []
    kept: list[dict] = []
    # An overview with more candidates than points tells each kind of event
    # once; an answer lists every distinct fact up to max_points.
    diversity = chronological and len(pool) > max_points
    for n in pool:
        h = _plain_headline(n.get("statement") or "")
        if not h or _restates_kept(n, kept, diversity=diversity):
            continue
        kept.append(n); heads.append(h[:1].upper() + h[1:])
        if len(heads) >= max_points:
            break
    on = _ON_HOST.get(lang, "on")
    heads = _tell_hosts_apart(heads, kept, on)
    points = list(heads)

    not_established = ("Nicht geklärt — keine Feststellung beantwortet die Frage direkt" if lang == "de"
                       else "Not established — no finding addresses this question directly")
    if chronological and heads:
        # An overview is one short story in time order, not a verdict.
        verdict = "Overview"
        # When and where, as far as known: "<span> on CORP-WS01: ",
        # "On CORP-WS01: " without a span.
        place = " ".join(p for p in (span, f"{on} {', '.join(hosts[:3])}" if hosts else "") if p)
        lead = (f"{place[:1].upper()}{place[1:]}: " if place else "") + "; ".join(heads[:4])
        heads = []
    elif kind == "yes_no" and (positive or negative):
        if rel_pos and any(_direct(n) for n in rel_pos):
            dkept: list[dict] = []
            for n in rel_pos:
                if (_direct(n) and _plain_headline(n.get("statement") or "")
                        and not _restates_kept(n, dkept)):
                    dkept.append(n)
            dheads = _tell_hosts_apart(
                [h[:1].upper() + h[1:] for h in
                 (_plain_headline(n.get("statement") or "") for n in dkept)], dkept, on)
            lead = f"{yes} — {dheads[0]}" if dheads else f"{yes} — {heads[0]}"
            heads = dheads[1:3]           # support only from findings that address it directly
            points = dheads or points
        elif rel_pos:
            # The finding shares the question's subject but not its words, or
            # is weakly supported: an indication, never a Yes.
            verdict = "Possible indicators, weakly supported"
            lead = ("Nur Hinweise — " if lang == "de" else "Indications only — ") + (heads[0] if heads else "")
            heads = heads[1:2]
        elif rel_neg:
            lead = (f"{no} — " + ("keine Belege gefunden" if lang == "de" else "no supporting evidence was found")
                    + (f"; {heads[0]}" if heads else ""))
            heads = heads[1:]
        else:
            verdict = not_established
            lead = verdict
            heads = heads[:2]
            if heads:
                heads = [("Verwandt: " if lang == "de" else "Related: ") + heads[0]] + heads[1:]
    elif positive and heads:
        # "What type of attack?" / "Which accounts?": the strongest finding
        # that addresses the question directly, said plainly, leads the
        # answer. "Indicators found" is a detection verdict and names no
        # value; whether every part is answered is not judged here. With no
        # direct finding the question is not established, and the related
        # findings are listed as such.
        # A finding addresses the question (rel_pos) when it shares its
        # words or its subject's vocabulary; a request for a relation is
        # addressed only by a stated relation.
        addressed = (any(_direct(n) for n in rel_pos) if relation_sides is not None
                     else bool(rel_pos))
        if addressed:
            verdict = "Leitbefund" if lang == "de" else "Lead finding"
            lead = heads[0]; heads = heads[1:]
        else:
            verdict = not_established
            lead = verdict
            heads = heads[:2]
            if heads:
                heads = [("Verwandt: " if lang == "de" else "Related: ") + heads[0]] + heads[1:]
    elif negative and heads:
        lead = ("Keine Belege gefunden" if lang == "de" else "No supporting evidence was found") + f"; {heads[0]}"
        heads = heads[1:]
    else:
        lead = verdict
    sentences.append(_terminate(lead))
    if heads:
        sentences.append(" ".join(_terminate(p) for p in heads))

    gap_points = [headline(n.get("statement") or "", limit=140, label_only=False) for n in gaps]
    if gap_points:
        sentences.append(
            f"This answer is limited: {len(gap_points)} area(s) of evidence "
            "were not examined (listed below) and could change it.")

    lead_node = pool[0] if pool else None
    return {
        "verdict": verdict,
        "lead": _terminate(lead),
        "text": " ".join(sentences).strip(),
        "lead_confidence": (str(lead_node.get("confidence") or "").upper() or None) if lead_node else None,
        "points": points,
        "gaps": gap_points,
        "confidence": confidence,
        "hosts": hosts,
        "timespan": span,
        "counts": {"affirmative": len(positive), "absence": len(negative),
                   "gap": len(gaps)},
    }


_GONE_STATUSES = frozenset({"superseded", "withdrawn", "dropped"})


# The forms an umbrella question takes — language, not case knowledge
# (English and German). "Which accounts were created?" names nothing
# either, but it asks for a specific fact and stays unanswered when no
# finding is linked to it.
_UMBRELLA_RE = re.compile(
    r"(?i)(?:what (?:happened|occurred|took place|went on)|summar|overview|"
    r"timeline|sequence of events|chain of events|course of events|describe|"
    r"narrative|big picture|passiert|geschehen|vorgefallen|geschah|"
    r"zusammenfass|überblick|ablauf|verlauf|beschreib|geschehnisse|hergang)")


# The words a request may use around an umbrella form without naming an
# item: the scope it asks about, not a thing to find.
_SCOPE_WORDS = frozenset({
    "host", "hosts", "system", "systems", "machine", "machines", "case", "event",
    "events", "network", "estate", "environment", "incident", "devices", "device",
    "rechner", "system", "systeme", "netzwerk", "fall", "vorfall", "ereignisse",
})


def is_general_question(text: str) -> bool:
    """A question about the case as a whole — an umbrella form that names
    nothing in particular after its lead label (no account, host, address,
    file, hash, time, and no item to find)."""
    body = request_body(text)
    if not body or not _UMBRELLA_RE.search(body):
        return False
    try:
        from core.investigation_tasks import link_tokens
        rest = _UMBRELLA_RE.sub(" ", body)
        named = [t for t in link_tokens(rest) if len(t) >= 4 and t not in _SCOPE_WORDS]
        if named:
            return False
    except Exception:  # noqa: BLE001 - the entity checks below still apply
        pass
    try:
        from core.entities import extract
        if extract(body):
            return False
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.claim_graph import statement_anchors
        if statement_anchors(body):
            return False
    except Exception:  # noqa: BLE001
        pass
    return True


def _when(node: dict) -> str:
    try:
        from core.claim_graph import statement_anchors
        ts = sorted(a for a in statement_anchors(str(node.get("statement") or ""))
                    if a[:4].isdigit())
        return ts[0] if ts else ""
    except Exception:  # noqa: BLE001
        return ""


def answer_for_task(task: dict, graph: dict,
                    narratives: dict[str, str] | None = None,
                    *, language: str = "en") -> dict[str, Any]:
    """The answer to one investigation question, from the beliefs linked to it.

    Pure projection over the claim graph — nothing is stored. Used by the
    report's "Answers to the Investigation Questions" section and by the
    dashboard's Questions tab, so the analyst reads the same answer in
    both places. Returns ``{"has_answer", "verdict", "text", "confidence",
    "supporting": [node dicts], "gaps", "missing_claim_ids"}``.
    """
    nodes = (graph or {}).get("nodes") or {}
    want = list(dict.fromkeys((task or {}).get("related_claim_ids") or []))
    related = [nodes[cid] for cid in want if cid in nodes]
    missing = [cid for cid in want if cid not in nodes]
    active = [n for n in related
              if str(n.get("status") or "") not in _GONE_STATUSES]
    # "What happened on the host?" names no account, file or address, so
    # word overlap never links a claim to it and the case's headline
    # question read "Not answered" under nine findings. A question with no identifiers in it is asking for the
    # whole picture: answer it from every active finding, and say so.
    overview = False
    question = str((task or {}).get("text") or "")
    if not related and is_general_question(question):
        active = [n for n in nodes.values() if isinstance(n, dict)
                  and n.get("kind") in ("claim", "observation", "conclusion")
                  and str(n.get("status") or "") not in _GONE_STATUSES]
        overview = bool(active)
    # A task the analyst never closed carries only what word overlap linked
    # to it — an exfiltration question answered by a firewall-log description,
    # an attack-type question by a "no RDP sessions" note. Until the task is
    # answered, the findings that speak to the question are the answer, the
    # linked ones first when they qualify.
    by_relevance = False
    if not overview and str((task or {}).get("status") or "") not in ("answered", "partial"):
        pool = [n for n in nodes.values() if isinstance(n, dict)
                and n.get("kind") in ("claim", "observation", "conclusion")
                and str(n.get("status") or "") not in _GONE_STATUSES]
        speaking = [n for n in pool if speaks_to(question, str(n.get("statement") or ""),
                                                  str(n.get("host") or ""), strict=True)]
        if speaking:
            def _lead(n):
                return first_sentence(n.get("statement"))
            linked_ok = [n for n in active if n in speaking]
            rest = sorted((n for n in speaking if n not in linked_ok),
                          key=lambda n: (not _shares_act(question, _lead(n)), -_rank(n),
                                         -_relevance(question, _lead(n))))
            active = (linked_ok + rest)[:10]
            by_relevance = True
    conclusions = [n for n in active if n.get("kind") == "conclusion"]
    claims = [n for n in active if n.get("kind") in ("claim", "observation")]
    primary = sorted(conclusions or claims, key=_rank, reverse=True)
    synth = synthesize_answer(str((task or {}).get("text") or ""), primary,
                              language=language, chronological=overview,
                              max_points=4 if overview else 3)
    text = (synth.get("text") or "").strip()
    if not primary or synth.get("verdict") == "Not answered":
        text = ""
    # A conclusion is the analyst's own one-sentence answer and takes the
    # lead; the finding summaries used to be pasted in here and read as a
    # wall of quotations instead of an answer, so they no longer are.
    lead = str(synth.get("lead") or "")
    conclusion_lead = False
    if text and conclusions and not str(synth.get("verdict") or "").startswith(("Not established", "Nicht geklärt")):
        text = " ".join(
            str(n.get("statement") or "").strip() for n in primary[:2])
        lead = first_sentence(str(primary[0].get("statement") or "")).strip()
        conclusion_lead = True
    confidence = synth.get("confidence")
    if by_relevance and synth.get("lead_confidence"):
        # The pill beside an open question describes the finding that leads
        # its answer, not the strongest finding that happens to be related.
        confidence = synth["lead_confidence"]
    if confidence is None and primary:
        best = max(_rank(n) for n in primary)
        confidence = next((k for k, v in _CONFIDENCE_RANK.items() if v == best), None)
    supporting = sorted(active, key=lambda n: (n.get("kind") != "conclusion",
                                               -_rank(n)))
    shape_gap = ""
    if text and not overview:
        shape_gap = answer_shape_gap(
            question, [str(n.get("statement") or "") for n in primary[:3]], language)
    if overview and text:
        # Chronological, since an overview is a story, not a ranking — and
        # capped: a reader wants the findings the story rests on, not the
        # whole catalogue repeated under every question.
        supporting = sorted(active, key=lambda n: (_when(n) or "~", n.get("id") or ""))
        supporting = [n for n in supporting if _rank(n) >= _CONFIDENCE_RANK["LIKELY"]][:8] or supporting[:8]
    return {
        "has_answer": bool(text),
        # Findings chosen for an open question are related material, not a
        # verdict: a yes/no question must not read "Yes" off a claim that
        # merely shares its subject.
        "verdict": ("Overview" if overview and text else
                    "Related findings" if by_relevance and text else synth.get("verdict")),
        "overview": overview and bool(text),
        "by_relevance": by_relevance and bool(text),
        "text": text,
        # The first sentence, written by the renderer: the prose pass may
        # carry the facts under it but never restate or replace it.
        "lead": lead if text else "",
        "conclusion_lead": conclusion_lead,
        "confidence": confidence,
        "supporting": supporting,
        "gaps": synth.get("gaps") or [],
        # The scaffold the written-prose pass rewrites: without these the
        # model is handed an empty headline list and, truthfully, writes
        # that no specific findings are documented.
        "points": synth.get("points") or [],
        "hosts": synth.get("hosts") or [],
        "timespan": synth.get("timespan") or "",
        "missing_claim_ids": missing,
        "shape_gap": shape_gap,
    }


def answer_is_only_gaps(answer: dict[str, Any]) -> bool:
    """True when nothing but unexamined-evidence statements back a question.

    The condition that must never be presented as an answer.
    """
    counts = (answer or {}).get("counts") or {}
    return bool(counts.get("gap")) and not (
        counts.get("affirmative") or counts.get("absence"))


# ── written-prose pass ────────────────────────────────────────────────────
#
# The projection above is exact but reads as an inventory: a lead sentence
# assembled from headline fragments, semicolon-joined. This turns that
# scaffold — never raw claim text — into a short written answer, over the
# same transport and role every other report narrative already uses
# (core.report_projection's ATLAS_REPORT_PROVIDER). The scaffold is the only
# source of facts the model is given, and the reply is checked back against
# it after: one naming an entity, or a host shaped like one, that the
# scaffold never mentioned is discarded, not repaired — the deterministic
# text above, never worse than what the analyst reads today, stands instead.

ANSWER_ROLE = "report"

# A token shaped like an asset name ("ORG-dc01", "EXAMPLE-FILE01")
# that is not one of the scaffold's own hosts is the one hallucination
# ``core.entities.extract`` cannot see — it only reads a host out of a UNC
# path, never bare prose.
_HOSTLIKE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]{1,15}-[A-Za-z0-9]{1,20}\d\b")


def _cache_path(case_dir) -> Any:
    from pathlib import Path
    return Path(case_dir) / ".atlas" / "answer_text_cache.json"


def scaffold_fingerprint(scaffold: dict[str, Any]) -> str:
    """Changes exactly when the facts an answer could rest on change: the
    deterministic text itself, and each supporting belief's id, status and
    confidence. Cheap and stable — no full claim prose is hashed."""
    import hashlib
    import json
    parts = [str(scaffold.get("text") or "")]
    for n in scaffold.get("supporting") or []:
        parts.append("|".join((str(n.get("id") or ""), str(n.get("status") or ""),
                               str(n.get("confidence") or ""))))
    parts.sort()
    return hashlib.sha256(json.dumps(parts).encode("utf-8")).hexdigest()[:16]


def _load_cache(case_dir) -> dict[str, Any]:
    import json
    try:
        return json.loads(_cache_path(case_dir).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a missing/corrupt cache is an empty one
        return {}


def _save_cache(case_dir, cache: dict[str, Any]) -> None:
    import json
    path = _cache_path(case_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001 — a cache write must never fail a report
        pass


def cached_answer_text(case_dir, task_id: str, fingerprint: str) -> str | None:
    """The synthesized prose for this exact scaffold state, or None — a
    plain file read, never a model call. Safe for a live dashboard request."""
    entry = _load_cache(case_dir).get(str(task_id) or "")
    if not isinstance(entry, dict) or entry.get("fingerprint") != fingerprint:
        return None
    text = entry.get("text")
    return text if isinstance(text, str) and text.strip() else None


def _carries(text: str, scaffold: dict[str, Any], question: str = "") -> bool:
    """False when the reply drops every fact the headlines carry. A fact is
    an entity a headline names - a file, an address, an account, a host, a
    time - that the question does not name itself; a reply carries it when
    it names one of them. Headlines that name no entity fall back to their
    content words beyond the question's, two of which must come through:
    one shared word ("spans") is coincidence, not content. A reply that
    restates the question and the verdict is the scaffold said worse, and
    the deterministic text stands instead."""
    from core.entities import extract
    from core.investigation_tasks import link_tokens
    heads = [str(h) for h in (scaffold.get("points") or []) if h]
    if not heads:
        return True
    entities: set[str] = set()
    for h in heads:
        entities |= {e.casefold() for e in extract(h)}
    entities -= {e.casefold() for e in extract(question)}
    if entities:
        if entities & {e.casefold() for e in extract(text)}:
            return True
        low = text.casefold()
        values = {e.split(":", 1)[1] if ":" in e else e for e in entities}
        return any(len(v) >= 4 and v in low for v in values)
    facts: set[str] = set()
    for h in heads:
        facts |= link_tokens(h)
    facts -= link_tokens(question)
    if not facts:
        return True
    return len(facts & link_tokens(text)) >= 2


def _grounded(text: str, scaffold: dict[str, Any]) -> bool:
    """False when the reply names an entity — or a host-shaped token — the
    scaffold never mentioned. The one check between a written answer and an
    invented one."""
    from core.entities import extract
    source = " ".join([
        str(scaffold.get("text") or ""),
        " ".join(scaffold.get("points") or []),
        " ".join(scaffold.get("gaps") or []),
        " ".join(scaffold.get("hosts") or []),
        str(scaffold.get("timespan") or ""),
        str(scaffold.get("verdict") or ""),
    ])
    if not extract(text) <= extract(source):
        return False
    known_hosts = {h.strip().lower() for h in (scaffold.get("hosts") or []) if h}
    return all(m.group(0).lower() in known_hosts
              for m in _HOSTLIKE_RE.finditer(text))


_ANSWER_SYSTEM_PROMPT = (
    "You write the supporting sentences of a short answer to a "
    "digital-forensics case question, for an incident responder. The "
    "answer's first sentence is already written and is given to you for "
    "context only: do not repeat, rephrase or contradict it. You are given "
    "the headline findings that support it, the hosts and time span "
    "involved, and evidence gaps. Write 1 to 3 plain sentences that carry "
    "each headline's facts, then — only if gaps are listed — one sentence "
    "on what remains unexamined. Use ONLY the facts given below. Do not add "
    "a host, date, account, address, file name or number that is not "
    "already there. State no conclusion, no position and no relation "
    "between the facts: do not say that two things are the same, linked, "
    "connected or that one proves, shows or confirms another; report each "
    "headline's own content. No event ids, hashes, record numbers or "
    "citation ids — those belong to the findings this answer cites. A reply "
    "that repeats the first sentence or the question without the headlines' "
    "content is wrong."
)

# Words with which a reply would state a relation or an inference the
# headlines do not: found in the reply and in no headline, the reply is
# refused and the deterministic text stands.
_INFERENCE_RE = re.compile(
    r"(?i)\b(?:identical|same|match(?:es|ed|ing)?|linked|links|connect(?:s|ed|ion)?|"
    r"correlat\w*|corresponds?|prove[sd]?|proving|confirm(?:s|ed|ing)?|demonstrat\w*|"
    r"establish(?:es|ed|ing)?|indicat(?:es|ed|ing) that|shows? that|showing that|"
    r"therefore|thus|hence|so the|which means|consequently|derselbe|dieselbe|dasselbe|"
    r"identisch|verknüpft|verbunden|belegt|beweist|zeigt,? dass|bestätigt|daher|somit|"
    r"folglich|deshalb)\b")


def _adds_relation(text: str, heads: list[str]) -> bool:
    """True when the reply states a relation or an inference that none of
    the headlines states."""
    said = {m.group(0).casefold() for m in _INFERENCE_RE.finditer(text or "")}
    if not said:
        return False
    given = {m.group(0).casefold() for m in _INFERENCE_RE.finditer(" ".join(heads))}
    return bool(said - given)


def _answer_user_prompt(question: str, scaffold: dict[str, Any], language: str) -> str:
    import json
    lang_name = "German" if (language or "en")[:2].lower() == "de" else "English"
    fields = {
        "question": question,
        "first_sentence_already_written": scaffold.get("lead") or "",
        "headlines": _support_points(scaffold),
        "hosts": scaffold.get("hosts") or [],
        "timespan": scaffold.get("timespan") or "",
        "gaps": scaffold.get("gaps") or [],
    }
    return (f"Language: {lang_name}.\n\n"
            f"Facts:\n{json.dumps(fields, indent=2, ensure_ascii=False)}\n")


def _support_points(scaffold: dict[str, Any]) -> list[str]:
    """The headlines the prose pass may carry: the scaffold's points minus
    the one the lead sentence already states."""
    try:
        from core.investigation_tasks import link_tokens
    except Exception:  # noqa: BLE001
        return [str(p) for p in scaffold.get("points") or [] if p]
    lead_toks = link_tokens(str(scaffold.get("lead") or ""))
    out = []
    for p in scaffold.get("points") or []:
        if not p:
            continue
        toks = link_tokens(str(p))
        # The lead's own headline says nothing the lead does not.
        if lead_toks and toks and toks <= lead_toks:
            continue
        out.append(str(p))
    return out


def _prose_checks(text: str, scaffold: dict[str, Any], question: str) -> bool:
    support = {**scaffold, "points": _support_points(scaffold)}
    return (_grounded(text, scaffold) and _carries(text, support, question)
            and not _adds_relation(text, support["points"]))


def synthesize_answer_text(case_dir, task_id: str, question: str,
                          scaffold: dict[str, Any], language: str = "en") -> str:
    """The scaffold's deterministic text, its lead sentence kept as written
    and the supporting facts upgraded to prose when an LLM provider is
    configured and the prose checks out — cached so the report and the
    dashboard read the same answer without a second call.

    The lead is the renderer's: a verdict, a conclusion's first sentence or
    the finding that answers directly. It is never written by the model.
    An answer that is not established, one led by a conclusion, and one
    with no supporting headline beyond the lead stay deterministic.

    Any failure (no provider, a network error, an empty or truncated reply,
    an ungrounded one, one that states a relation the headlines do not)
    falls back to the deterministic text: this never returns something
    worse than ``scaffold["text"]``, and never raises.
    """
    deterministic = str(scaffold.get("text") or "")
    if not deterministic:
        return deterministic
    lead = str(scaffold.get("lead") or "").strip()
    verdict = str(scaffold.get("verdict") or "")
    if (not lead or scaffold.get("conclusion_lead")
            or verdict.startswith(("Not established", "Nicht geklärt", "Not answered"))
            or not _support_points(scaffold)):
        return deterministic
    fingerprint = scaffold_fingerprint(scaffold)
    cached = cached_answer_text(case_dir, task_id, fingerprint)
    # A cached reply is held to the same checks as a fresh one: the checks
    # may have sharpened since it was written, and prose that no longer
    # passes them is not an answer whatever its fingerprint says.
    if cached is not None and cached.startswith(lead) and _prose_checks(cached[len(lead):], scaffold, question):
        return cached
    try:
        from core import providers
        provider = providers.resolve(
            providers.role_name("ATLAS_REPORT_PROVIDER", "ATLAS_AGENT_PROVIDER"))
        if not provider.api_key or not provider.model:
            return deterministic
        from agent.llm import LLMHubClient
        client = LLMHubClient(
            base_url=getattr(provider, "base_url", ""),
            api_key=getattr(provider, "api_key", ""),
            model=getattr(provider, "model", ""),
            timeout=60, provider=getattr(provider, "name", ""))
        resp = client.chat(
            [{"role": "system", "content": _ANSWER_SYSTEM_PROMPT},
             {"role": "user", "content": _answer_user_prompt(question, scaffold, language)}],
            role=ANSWER_ROLE, temperature=0.2)
        text = (resp.content or "").strip()
        if not text or resp.finish_reason == "length" or not _prose_checks(text, scaffold, question):
            return deterministic
    except Exception:  # noqa: BLE001 — the deterministic answer always stands
        return deterministic
    text = lead + " " + text
    cache = _load_cache(case_dir)
    cache[str(task_id)] = {"text": text, "fingerprint": fingerprint}
    _save_cache(case_dir, cache)
    return text
