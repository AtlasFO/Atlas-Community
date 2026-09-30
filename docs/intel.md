# Threat context: supplying indicators and reports to a case

Most investigations start with something already known: indicators from an
alert, a feed your organisation subscribes to, a report a partner shared.
`atlas intel` hands them to a case in the formats your tools already export.
Atlas keeps them in `.atlas/threat_context.json`, one row per indicator with
the name of the source it came from.

## What a row means

A row is a lead from its source, never a fact about the evidence:

- Presence in this case is shown only by a tool call whose output holds the
  value. The row itself proves nothing.
- A maliciousness rating stays the source's claim. The model cites the row id
  (`intel-0003`) when it repeats one.
- A value that was not found is a statement about what was searched, never
  "clean".
- At least one finding should stand on evidence found without the list.

Rows are never deleted. `atlas intel withdraw` retires them with a reason. A
value too generic to search for (a loopback address, the digest of empty
input, a public resolver, a network range, a common word) is kept as *unfit*
with the reason and is never searched. A row the source lists as benign
(`malicious: false`) is shown as such and is otherwise inert.

The record belongs to the case, like its claims and questions: a fresh run
and a rerun keep it. On a graded case (one that ships an answer key) intake is
refused, because supplied indicators would make the score unmeasurable.

## Adding files and reports

```
atlas intel add --case ~/cases/c1 --file iocs.txt
atlas intel add --case ~/cases/c1 --file export.csv --map value=Indicator,type=Kind --tlp amber
atlas intel add --case ~/cases/c1 --file bundle.json --name "partner feed"
atlas intel add --case ~/cases/c1 --doc report.pdf
atlas intel list --case ~/cases/c1 --all
atlas intel withdraw --case ~/cases/c1 --id intel-0007 --reason "sinkholed since March"
atlas intel sources
```

Built-in readers (`--format`, detected when omitted):

| Reader | Input |
|---|---|
| `lines` | one value per line; `#` starts a comment; the type is detected |
| `csv` | a table with a header; value, type, description, confidence, tlp, first_seen, last_seen, malicious and labels columns are found by their common names, `--map field=column` overrides |
| `stix2` | a STIX 2.1 bundle: cyber-observable objects, and indicator patterns that are a plain `OR` of equality comparisons; any other pattern is kept as an unfit row with its text |
| `misp` | MISP event JSON (one event, a list, or a search response); attribute types are mapped, composite types give one row per part, `to_ids` marks the row as rated malicious, `tlp:` tags set the TLP |
| `atlas-jsonl` | the native interchange below |

`--doc` reads a threat report (plain text, HTML, or PDF through poppler's
`pdftotext`), keeps its text under `.atlas/intel_docs/`, and records the
addresses, domains, URLs, mail addresses, hashes, paths, registry keys and
accounts it names as rows nobody rated. Bare file names in prose are left out;
a name whose extension is also a top-level domain (report.zip, run.py) is read
as a file, a bare `.com` name as the domain.

Every row passes the same type checks as the indicators a run records
(`core/indicators.py`): an IP must parse, a hash must be MD5, SHA-1 or
SHA-256, a domain must end in a delegated top-level domain. A row that fails
is kept as unfit with the reason.

## The native interchange (`atlas-jsonl`)

One JSON object per line. Only `value` is required:

```json
{"value": "203.0.113.7", "type": "ip", "description": "C2 seen in campaign X",
 "malicious": true, "confidence": 80, "tlp": "amber", "labels": ["c2"],
 "first_seen": "2026-03-01", "last_seen": "2026-04-12"}
```

`type` is one of `ip, mac, domain, url, email, hash, path, file, registry,
service, task, account, host, serial, cloud_resource, credential_id, pattern`
(common spellings such as `ipv4`, `md5`, `fqdn`, `hostname` are accepted).
`tlp` is `clear`, `green`, `amber`, `amber+strict` or `red`. Anything that can
print this format can feed Atlas.

## Command sources

A platform with a command line or an HTTP API feeds a case through a command
you configure in `.env`. Atlas runs it, reads what it prints with the named
reader and keeps the output under `.atlas/intel_docs/pulls/`:

```
ATLAS_INTEL_SOURCES=feed,sandbox
ATLAS_INTEL_SOURCE_FEED_COMMAND=/opt/intel/export-case --case {case_id} --format stix
ATLAS_INTEL_SOURCE_FEED_FORMAT=stix2
ATLAS_INTEL_SOURCE_FEED_TIMEOUT=120
ATLAS_INTEL_SOURCE_SANDBOX_COMMAND=curl -sf -H @/etc/atlas/sandbox.headers https://sandbox.internal/iocs.csv
ATLAS_INTEL_SOURCE_SANDBOX_FORMAT=csv
```

```
atlas intel pull --case ~/cases/c1 --source feed
```

The command is split into arguments and run without a shell. `{case_id}` (the
case folder's name) and `{case_dir}` are substituted inside each argument, so
a value can never add an argument. Credentials stay with your command; Atlas
stores none. Only an operator runs a source: the model has no tool for it.

## A reader for your own format

Ship a reader as an addon (see `docs/addons.md`):

```python
from core.addons import Addon, intel_reader


class OurExport(Addon):
    name = "our_export"

    @intel_reader("our-export", suffixes=(".ourx",))
    def read(self, path: str):
        for rec in parse_our_format(path):
            yield {"value": rec.observable, "type": rec.kind, "description": rec.note}
```

`atlas intel add --file x.ourx` then picks it by suffix, `--format our-export`
names it, and a command source can use it as its `_FORMAT`. Rows from an addon
pass the same type checks as every other row.

## In a run

The system prompt carries a THREAT CONTEXT block: the rules above and the
active rows, fenced as data, at most 150 rows or 6 KB (rows the source rates
malicious first; the rest stay in the file). A description that addresses an
automated reader is withheld. Up to half of the indicator-pivot ledger is
seeded from the rows, so the run is reminded to search for them in each
evidence class.

- **The sweep.** `search.intel_sweep` searches everything command-line tools
  printed so far (the full-output evidence index) for every active row at
  once and confirms each hit with the same type-aware test typed indicators
  pass. A hit names the call whose output shows the value; a finding cites
  that call. The sweep's own output lists the values it looked for, so citing
  it shows nothing. What in-process tools returned (table queries, parsers
  Atlas runs itself) is not in the index; the sweep says so, and a row it did
  not find is a statement about what was searched.
- **Ratings.** A finding may repeat a source's rating ("a malicious address
  per intel-0003"). The external-knowledge gate accepts it when the row is
  active, the finding names its value, and a cited evidence call shows that
  value: the rating is the source's, the presence is the evidence's.
- **No exoneration from a miss.** At any tier, a finding that turns a value
  not found into a verdict ("not found, the host is clean") is refused. The
  search goes into a disposition note that says what was searched and where.
- **Anchoring.** When every CONFIRMED or LIKELY finding cites a row or names
  one of its values, the pre-report check says so and the report states that
  every finding rests on the supplied indicators. `ATLAS_INTEL_ANCHOR_BLOCK=1`
  makes this a blocker for organisations that want it.
- **TLP.** A value from a row marked `red` or `amber+strict` is never sent to
  an outside service: the enrichment tools refuse it, whatever the row's
  status. The report withholds such values.
- **Report.** Scope and Evidence gains a "Threat context" block: the sources,
  the rows by status, the last sweep with the findings that cite its hits, and
  the unfit rows.

Intel is never ingested into Atlas's knowledge base (the brain): it learns
from findings, which have to rest on evidence.
