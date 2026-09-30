## Cross-tool correlation (`correlate.*`)

- `correlate.process_to_file(pid=…, path_substring=…)` — join vol process listings to MFT/fls records
- `correlate.network_to_process(ip=…, port=…)` — join vol.netscan/netstat to vol.pslist by PID
- `correlate.mitre_map(finding_text=…, top_n=…)` — rank candidate ATT&CK IDs by keyword score
- `correlate.mitre_validate(technique_id=…)` — confirm a technique ID exists

Any ATT&CK ID (`T\d{4}(\.\d{3})?`) in a finding description is **auto-validated** by `record_finding` (gate: `mitre_technique_validation`). Unknown IDs refuse with the offending strings. Manual `correlate.mitre_validate` is still useful for pre-finding scouting; use `correlate.mitre_map` to find candidates for a behaviour you don't yet have a T-ID for.

---
