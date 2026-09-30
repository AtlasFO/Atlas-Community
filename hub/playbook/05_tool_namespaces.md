## Atlas MCP Tool Namespaces

All forensic execution goes through MCP tools.

### Evidence profile (facts, not a playbook)

At run start Atlas builds `.atlas/evidence_profile.json` from `evidence/` —
which artifact **classes** are present (disk, memory, pcap, tabular,
windows_eventlog, …) and which are absent. That inventory is injected into
the system prompt and used by the **evidence-compat gate**.

The agent must call **`misc.inventory_evidence`** immediately after
`start_execution_log`. That assessment answers: what exists, what is
already parsed (consume first), what still needs processing, and what
to skip. A hard **evidence-assessment gate** blocks mounts, parsers,
hunters, table queries, hash verify, `reason.*`, and `dair` until the
latch is stamped. `misc.list_evidence_dir` may explore basenames but
does **not** unlock the gate.

**Discovery-first (global):** never invent filenames, export names, or
layouts. If you do not already know an exact path, call
`misc.list_evidence_dir` / use inventory `already_processed` / class
samples. Middleware refuses invented paths (`gate: discovery_first`) and
will auto-bind only when discovery finds a unique match. Do not retry the
same missing path.

- **Your job:** choose strategy and tools among what is compatible.
- **Hard line:** tools that require a class this case does not contain are
  refused (e.g. `ewf.*` without a disk image, `vol.*` without memory,
  `ez.evtxecmd` without EVTX or a disk image that could contain them).
  **Structural rule:** image/volume openers (`ewf`, `tsk`, `img`, …) need
  `disk`; path-consuming artifact parsers (`ez.*` and similar) accept
  `file` **or** `disk` (KAPE/loose extracts are `file`). Do not add
  per-tool exceptions — new EZ tools inherit the `ez_` prefix rule.
- **Not hardcoded:** there is no fixed “if CSV then always X” path — within
  the compatible set, investigate freely.
- Core namespaces preload from the profile (tabular cases get `table.*`,
  not `ewf.*`); you may still `atlas_load_namespaces` others, but impossible
  combinations fail at the gate — treat that as a signal, not a retry loop.

| Namespace | Domain | Key Tools |
|-----------|--------|-----------|
| `img.*` | Disk image prep | **`vmdk_chain_info` → `vmdk_export_raw`** for VMDK (TSK/xmount cannot open VMDK chains); then hand off to `tsk.mmls`. `losetup` / `xmount` are demoted in Triage — use only in Collect/Analyze after TSK orientation when an offset loop mount is explicitly required. Also: ewfmount helpers, vshadowmount, bdemount, photorec |
| `vol.*` | Memory (Volatility 3) | **`vol_symbol_check` first on any new image**, then pstree, pslist, psscan, cmdline, netstat, dlllist, malfind, hivelist, dumpfiles, linux plugins |
| `tsk.*` | Filesystem (Sleuth Kit) | **`mmls` first on raw/exported images**, then fls, icat, istat, ils, blkls, mactime, tsk_recover, sigfind, sorter, jls, jcat, **indxparse** ($INDX slack); `tsk.recover` takes `dir_inode` (from `tsk.resolve_path`) for one directory tree, `whole_volume=True` only when the full extraction is meant; single files via `tsk.icat` |
| `ewf.*` | E01 images | ewfmount, ewfinfo, ewfverify, mount_full_image |
| `ez.*` | Windows artifacts (EZ Tools) | MFTECmd (`resident=inline` puts small files' content in the CSV: scripts, shortcuts and Zone.Identifier streams kept inside their MFT record; `resident=dump` writes them out; `include_slack` recovers FILE record slack), **mftecmd_usn** ($J change journal with full paths when given the $MFT; one file's history is a table.table_query filter on Name or ParentPath), EvtxECmd, RECmd, AmcacheParser, AppCompatCacheParser, PECmd, JLECmd, LECmd, SBECmd, WxTCmd, SQLECmd, RBCmd, SrumECmd (SRUM: per-app network bytes), **sumecmd** (Server User Access Logging: who used which role from which address, per day; the whole Windows/System32/LogFiles/Sum folder), bstrings (a regex sweep over `$LogFile` or any binary) |
| `plaso.*` | Super-timeline | log2timeline, psort (CSV/JSON/filter), pinfo |
| `yara.*` | Threat hunting | scan_file/_directory/_memory_image, scan_strings, compile_rules — built-in rules at `~/atlas/rules/` |
| `hash.*` | Integrity / similarity | hash_file (cached), hash_directory, ssdeep, hashdeep, verify_evidence_hash |
| `strings.*` | Static analysis | strings, hexdump, xxd, file, exiftool, stat, **floss_extract** (obfuscated strings) |
| `carve.*` | File carving | bulk_extractor, foremost, scalpel |
| `ese.*` | ESE databases (SRUM raw, WebCache, Windows.edb) | esedb_info, esedb_export (one text file per table) |
| `evt.*` | Legacy .evt event logs (NT to XP/2003; .evtx belongs to ez/chainsaw/hayabusa) | evt_export |
| `steg.*` | Steganography | steg_extract (steghide, outguess, jpseek in turn; `image_path` and `passphrase` each take one value or a list, so a carriers x passphrases search is one call that ends in the payloads found or a countable negative; passphrases come from the evidence, never guessed), steg_status |
| `net.*` | Network analysis | tcpdump_read, tcpdump_extract_http/dns, ngrep_search, tcpxtract_streams |
| `enrich.*` | Threat intel | **vt_lookup_hash/ip/domain**, abuseipdb_check, **otx_lookup** (pulses: malware family + adversary), passive_dns, urlscan_search, misp_lookup, whois_lookup, oui_lookup, enrichment_status (all degrade gracefully without keys; a rejected key or exhausted quota returns `success:false` with the HTTP status, never an empty "clean" verdict) |
| `misc.*` | Windows artifacts + email + macros | regripper, usn_journal, Hindsight, ClamAV, PDF/PE, **evtx_filter**/**evtx_dump** (EVTX by Event ID and time window, or to XML — pure Python, no .NET), **analyzemft_parse** ($MFT → CSV without .NET), **mft_rule_hunt** (an extracted $MFT, deleted entries included, against chainsaw's public $MFT rules: offensive and remote-access tools, credential-store copies), **pff_export**, **readpst_extract**, **densityscout_scan**, **chainsaw_hunt** (Sigma), **capa_analyze** (caps→ATT&CK), **olevba_scan**/**mraptor_scan**, **device_install_inventory** (complete USB/BadUSB device table from setupapi.dev.log), **onedrive_odl** (OneDrive sync logs: uploads, downloads, renames, deletes; pass the account's settings folder so obfuscated names decode), **batch_run** |
| `reason.*` | Adversarial review (swappable via REASON_BACKEND) | plan, hypothesize, evaluate_finding, **confidence_score**, cite_check, synthesize, pre_report_check |
| `correlate.*` | Cross-tool correlation | **process_to_file**, **network_to_process**, **mitre_map**, **mitre_validate** |
| `accuracy.*` | Ground-truth comparison | accuracy_compare, accuracy_export_report (precision, recall, F1, negative-coverage) |
| `dair.*` | DAIR phase director (separate backend via DAIR_BACKEND) | dair_assess — call after every tool batch |
| `af.*` | Anti-forensics detection | **timestomp_drift** (after ez.mftecmd), **event_log_clear** (after ez.evtxecmd), **sysmon_evasion** (after ez.recmd SYSTEM), **usn_gaps** (after misc.usnparser_parse), **prefetch_deletion** (after ez.pecmd / amcacheparser) — run automatically when the input artifact exists |
| `live.*` | Live endpoint analysis (Linux/SSH, read-only) | live_processes, live_network_connections, live_persistence_audit, live_yara_scan, live_open_files, live_read_file, live_event_log_tail |
| `velo.*` | Velociraptor API surface (read-only WRT evidence) | list_clients, client_info, collect_artifact, wait_for_flow, get_collection_results, get_client_event_table, update_client_event_table, upload_artifact_yaml, query |
| `monitor.*` | Live-monitoring lifecycle | baseline_capture, start_watcher, stop_watcher, list_watchers, check_alerts, ack_alert |
| `respond.*` | **Gated** containment & eradication (live-monitoring scope only) | suggest_containment, list_actions, approve_action, execute_action, revert_action |
| `search.*` | FTS over all gathered tool output (full text, incl. spilled) | **search_evidence** (IOC pivot before re-running tools; hits cite call_id), search_index_status |
| `job.*` | Detached background jobs for hours-long tools (plaso, carvers, hayabusa) | job_start_* (returns immediately with job_id + batch_id), **job_wait / job_wait_all** (block + collect — use instead of job_status polling), job_status, job_collect, job_cancel, job_list |
| `export.*` | Machine-readable deliverables (run alongside the final report) | **export_navigator** (ATT&CK Navigator layer from gate-validated techniques), **export_iocs** (STIX 2.1 bundle + IOC CSV from CONFIRMED/LIKELY findings, citable via finding call_id) |

**Background-job discipline (`job.*`).** Any tool expected to run >10 min (full plaso timeline, bulk_extractor/foremost/scalpel carve, Hayabusa over large EVTX sets) goes through `job.job_start_*` — never its blocking synchronous twin. Start the whole foundation batch EARLY (first Collect pass), keep investigating other leads while it runs, then `job.job_wait_all()` (or `job_wait(job_id)`) right before you need the results — one blocking call that collects everything, instead of a `job_status` poll per turn. Jobs started in the same DAIR batch share a `batch_id`; identical re-submissions are deduplicated onto the existing job (`deduplicated: true` — wait on it, don't re-run). Collected output is trace-linked to the start entry and FTS-indexed, so `search.search_evidence` covers it.

---
