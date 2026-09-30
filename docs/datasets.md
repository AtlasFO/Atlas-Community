# Datasets

*The bundled demo, and public datasets to point Atlas at.*

Evidence is not included in the repository: disk images and captures are
large, and are best fetched from their authoritative source, which each dataset
below links to.

## Bundled

| Case | What ships | Dataset |
|------|------------|---------|
| **RHINO-HUNT** | A finished run: the case brief, the execution trace, the run's state and the reports, so every dashboard tab has content. Browse it with `./dashboard.sh --demo`. | DFRWS 2005 Rodeo Challenge "Rhino Hunt": a USB key image (`RHINOUSB.dd`) and three network traces, [CFReDS archive](https://cfreds-archive.nist.gov/dfrws/Rhino_Hunt.html); [official answers](https://cfreds-archive.nist.gov/dfrws/DFRWS2005-answers.pdf) |
| **NITROBA-2008** | The case brief, ready to run: put `nitroba.pcap` into a new `demo-cases/nitroba/evidence/` folder and start the run. At about 54 MB it is the lightest fresh run. | Nitroba University Harassment Scenario, [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/) |

A bundled case with a finished run holds:

```
demo-cases/<case>/
├── CASE.md                      ← the case brief: Case ID and the investigation requests
├── .atlas/                      ← the run's state: claim graph, questions, report projection
├── analysis/<CASE>_trace.json   ← the execution trace, the dashboard's input
└── reports/                     ← the reports and the exported trace
```

## More public datasets

Each of these runs as a case of your own: copy `case-template/` to
`~/cases/<CASE_ID>`, put the evidence under `evidence/`, write the questions
into `CASE.md` and start the run ([try-it-out.md](try-it-out.md), Path B).

| Dataset | Evidence |
|---------|----------|
| NIST CFReDS Data Leakage Case | A PC image, two USB images and a CD-R, [cfreds.nist.gov](https://cfreds.nist.gov/all/NIST/DataLeakageCase) |
| NIST "Hacking Case" (Greg Schardt, "Mr. Evil") | A notebook disk image, [CFReDS archive](https://cfreds-archive.nist.gov/Hacking_Case.html) |
| M57-Jean (M57.biz scenario) | A Windows XP disk image, [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/m57-jean/) |
| 2018 Lone Wolf scenario | A Windows 10 disk image, a memory image and the pagefile, [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/) |
| The Stolen Szechuan Sauce | A domain controller and a desktop, each with disk and memory, plus a network capture, [DFIR Madness](https://dfirmadness.com/the-stolen-szechuan-sauce/); [answers](https://dfirmadness.com/answers-to-szechuan-case-001/) |

## Scoring a run

`atlas train` runs a case afresh and has an independent reviewer grade the
run. A case with a machine-readable answer key, `ground_truth.json` at its
root, is also scored against it: precision, recall and F1 over the expected
findings. The key looks like this:

```json
{
  "case_id": "MY-CASE",
  "expected_findings": [
    {"id": "GT1", "description": "what the finding should say", "confidence_min": "LIKELY"}
  ],
  "negative_assertions": ["a claim the run must not make"]
}
```
