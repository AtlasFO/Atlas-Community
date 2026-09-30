# Indicators — RHINO-HUNT

Frame: incident on the owner's systems. Attacker rows are block and hunt items; the owner's own assets are listed under Scope, never as block items.
Own-asset basis: evidence links, graph hosts, brief tables, appositions; P0 baseline pending.
Verify ownership before deploying a block item.

18 typed indicator(s), 0 own asset(s) and 1 prose-derived candidate(s) from 22 recorded belief(s). Every row cites the claim it came from; nothing here is inferred from raw tool output.

## Block at the perimeter

| Value | Type | Side | Confidence | First seen | Last seen | Host | Finding |
|---|---|---|---|---|---|---|---|
| 137.30.120.40 | ip | attacker | LIKELY |  |  | RHINOUSB, 137.30.122.253 | C0015, C0016, C0017, C0003, C0004, C0014, C0019, C0021, N0022 |
| 137.30.120.37 | ip | attacker | LIKELY |  |  | RHINOUSB | C0016, C0017, C0011, C0012, C0014, C0021, N0022 |
| 137.30.122.253 | ip | attacker | LIKELY |  |  | RHINOUSB, 137.30.122.253 | C0015, C0016, C0004, C0018 |
| 137.30.123.234 | ip | attacker | LIKELY |  |  | RHINOUSB | C0016, C0011, C0012 |
| bighonkingrhino@hotmail.com | email | attacker | LIKELY |  |  | 137.30.122.253 | C0018, C0019 |
| hugerhinolover@hotmail.com | email | attacker | LIKELY |  |  | 137.30.122.253 | C0018, C0019 |

## Contain: disable or isolate

| Value | Type | Side | Confidence | First seen | Last seen | Host | Finding |
|---|---|---|---|---|---|---|---|
| gnome | account | attacker | LIKELY |  |  | RHINOUSB, 137.30.122.253 | C0004, C0014, C0015, C0016, C0017, C0018, C0019 |

## Hunt across the estate

| Value | Type | Side | Confidence | First seen | Last seen | Host | Finding |
|---|---|---|---|---|---|---|---|
| gnome | account | attacker | LIKELY |  |  | RHINOUSB, 137.30.122.253 | C0004, C0014, C0015, C0016, C0017, C0018, C0019 |
| rhino.exe | file | attacker | LIKELY |  |  | RHINOUSB | C0012 |
| gnome123 | credential_id | attacker | LIKELY |  |  | RHINOUSB | C0004, C0016 |
| gumbo | credential_id | attacker | SUSPECTED |  |  | RHINOUSB | C0020 |
| cook.cs.uno.edu | host | attacker | LIKELY |  |  | 137.30.122.253 | C0019 |
| contraband.zip | file | attacker | LIKELY |  |  | RHINOUSB | C0004 |
| rhino1.jpg | file | attacker | LIKELY |  |  | RHINOUSB | C0004 |
| rhino3.jpg | file | attacker | LIKELY |  |  | RHINOUSB | C0004 |
| rhino4.jpg | file | attacker | LIKELY |  |  | RHINOUSB | C0011 |
| rhino5.gif | file | attacker | LIKELY |  |  | RHINOUSB | C0011 |

## Identify

| Value | Type | Side | Confidence | First seen | Last seen | Host | Finding |
|---|---|---|---|---|---|---|---|
| gumbo1.txt | file | subject | LIKELY |  |  | RHINOUSB | C0008 |
| gumbo2.txt | file | subject | LIKELY |  |  | RHINOUSB | C0008 |

## Review before use

Parsed from the wording of a belief, not stated by the analyst: confirm each value against its finding before it enters a block list or a hunt.

| Value | Type | What the belief says | Finding |
|---|---|---|---|
| x04 | account | account involved in attacker activity | C0015 |
