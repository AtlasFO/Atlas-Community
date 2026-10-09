# Changelog

All notable, user-visible changes to Atlas. Newest first.

## How to add an entry

Add one line under **Unreleased** for every change a user of Atlas will
notice: a different report, a run that behaves differently, a new or removed
tool, a new setting. Describe the effect, not the implementation. Internal
refactors, test-only changes and documentation need no entry. The pre-commit
hook reminds you when a commit changes code without touching this file.

## Versions

Every push raises the version (`ATLAS_VERSION` in `core/plugins.py`): the
third number for fixes and small improvements (1.0.1), the second for bigger
changes (1.1.0), the first only by the owner's decision. The update's commit
moves the Unreleased lines under a heading for the new version.

## Unreleased

## 1.0.1 — 2026-10-09

What you already know:

- The analyst model reads each statement in a block of
  its own, with an id, under one set of rules in runs, reruns and chat. A fact
  about your own systems (an admin host, a service account) is read as
  context, not as a suspicion, so its routine activity is no longer recorded
  as a finding; a suspected indicator found in the evidence still is.
- A fact added to a long CASE.md is no longer cut from what the model reads,
  and the template's comments no longer reach it.
- Indicators pasted in a code fence under What you already know are searched
  for; AI Autofill names any it would drop instead of deleting the block.
- The report's Scope and Evidence section lists each statement with the
  findings that name what it names.

Analysis:

- A disk image counts as examined only once a tool has read its filesystem;
  reading its partition table no longer counts, and an image can be marked
  unreadable only after a read of it failed. `atlas rerun` recounts which disk
  images a tool actually read and asks the investigator to read the rest.
- A run or rerun in its report phase is no longer wrapped up while it reads
  evidence the report gate still lists as unread, or closes requests and their
  parts; a rerun no longer starts from the previous run's gate verdicts. A deep
  dive into evidence already read that closes nothing and resolves no blocking
  issue still wraps up, after 36 report-phase turns at the default settings.
- The report phase no longer loops on the same pre-report objections: a
  repaired finding replaces the old one instead of standing beside it, and a
  finding that keeps failing the same check is lowered.
- Table searches scan the whole file by default; when a scan stops early the
  result says so, and an empty result from it is no longer taken as proof that
  something is absent.
- Event logs or mail missing as loose files beside disk images are reported as
  possibly inside the images, not as unavailable.
- Memory images are recognised by their content: a raw memory capture named
  `.img` or `.raw`, a crash dump or a hibernation file is offered to
  Volatility, and the kind given in the Evidence Links table wins.
- INDX slack parsing lists deleted entries from recent years (entries dated
  2024 or later were dropped before), and an `$MFT` given to it is refused with
  a pointer to the right tool.
- A typed indicator with a wrong value (for example a hash one character too
  long) no longer disappears silently: the IOC report lists it under "Not
  exported", and the pre-report check says how to correct it.
- Paths written in a code span or followed by a bracket or a quote are
  recognised without that character.
- Answers to the case's questions no longer merge distinct facts that share a
  long opening, and the same fact on two hosts stays two points, each naming
  its host. An overview answer without a time span opens with "On <host>:".
- Request parts are answered more precisely: a value part is answered by the
  value the question asks for, or the run is asked which value it means; "an
  executable" is answered by a program file; an account given with its SID
  shows with its name; a device numbered #2 is not answered by a finding about
  #3. A finding with a trailing caveat ("...; the browser history was not
  parsed") is read as a finding, not as an open gap.
- The artifact-value list names each user profile's and each host's copy of a
  file separately.
- A quoted job or task name ("the job 'Nightly Sync'") is no longer taken for a
  person when a finding is recorded; a quoted person in an accusation is still
  checked.

Runs, reruns and CASE.md:

- A stopped run's report includes the IOC files and the recorded response
  plan; the report's Recommendations always show the recorded plan.
- `atlas rerun` reuses the recorded hashes of evidence files that did not
  change; `--full-hash` re-hashes everything.
- The dashboard shows the intake's progress (files and GB fingerprinted) while
  a run, train or rerun prepares the evidence, and a Stop during intake is
  recorded as an interrupted run.
- A code block that is never closed in CASE.md is reported at run start,
  rerun, AI Autofill and in the dashboard's Brief page; `atlas run` and
  `atlas train` refuse to start when it hides investigation requests.
- A separator line (`---`, `* * *`) in CASE.md is no longer passed to the
  model with What you already know, and no longer read as an investigation
  request or an Evidence Links entry.
- `atlas train` hides every answer-key copy in the case by its name (also
  `ground_truth.<language>.json` and copies outside the usual places).
- `atlas review --case DIR` grades a finished run from its trace without
  touching a running process, including accuracy and TTP coverage, and writes
  the review into that case. With several runs live, `atlas review` without
  `--case` asks which case to grade, and tools started outside a case no
  longer attach to the run started last.

Dashboard and reports:

- Report downloads work again for cases after a rerun, in every format, and
  the Report tab and the Overview open the main report by default. Markdown
  downloads are byte-exact, and reports whose names contain special characters
  download and preview correctly.
- The HTML report export no longer runs code or loads anything: markup quoted
  from evidence shows as text, and links keep only web and mail targets.
- Files from case folders opened in the dashboard are shown as text or
  downloaded, never run inside the dashboard. A trace opened in the dashboard
  can no longer run script, whatever its fields hold.
- The dashboard serves only its own pages and their assets; its program files
  can no longer be downloaded.
- The header's run status shows the right case right after sign-in and when
  you switch cases.

Install and providers:

- The Atlas SMB share requires encryption on its own section, wherever its
  include lands in the host's smb.conf.
- A corrupt prefetch file no longer stops the fallback prefetch parser; the
  rest of the folder is parsed.
- INSTALL_INSTRUCTIONS.md says which tools are pinned and which are fetched at
  their current upstream version.
- The `anthropic` provider preset keeps working when a model refuses the
  thinking or temperature settings it is sent.

## 1.0.0 — 2026-09-30

First public release. What Atlas does, how to install it and how to run a
case: [README.md](README.md).
