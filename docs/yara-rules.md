# YARA rules — bring your own

Atlas ships a small rule set under `rules/` and scans with it by default.
The folder is read, not registered: **drop a `.yar` or `.yara` file into
`rules/` or any sub-folder and the next scan uses it.** No list to edit, no
restart, nothing to tell Atlas.

## How the bundled set is used

Every `yara.*` tool (`scan_file`, `scan_directory`, `scan_process_memory`)
takes an optional `rules_path`. When the investigation calls one without
it, Atlas compiles everything under `rules/` — recursively, `.yar` and
`.yara` — into one rule set and scans with that (`tools/yara_tools.py`,
`bundled_rules_dir()` and `_compile_rules()`). The sub-folders
(`cobalt_strike/`, `persistence/`, `lateral_movement/`, …) are only
organisation; a file's path relative to `rules/` becomes its YARA
namespace, so a match reports which file it came from.

The rules that ship are Atlas's own (`author = "Atlas"` in every `meta`
block); they cover Cobalt Strike artefacts, persistence, lateral movement,
PowerShell injection and anti-forensics.

## Adding rules

1. Put the file under `rules/`, in an existing sub-folder or a new one.
   Any name; `.yar` or `.yara`.
2. Check it compiles: `yara.compile_check` on the file (from `atlas chat`,
   or run the tool from a case). A rule set is compiled as one unit, so a
   syntax error in **any** file makes every YARA scan report
   `success: false` with the compiler's message until it is fixed — the
   scan never crashes, it just returns the error.
3. That is all. The next `yara.*` call picks it up.

Rule *names* only have to be unique within a file (each file is its own
namespace); files may share a name across sub-folders. A `meta` block with
`description`, `author` and `severity` is the convention the bundled rules
follow, and the report shows `meta` on a match.

## Using a different set for one scan

Pass `rules_path` — a single file or a directory — and Atlas compiles that
instead of the bundled set. `inline_rule` takes complete rule text for a
one-off check. Exactly one of the two, never both.

## Not this mechanism

Sigma rules are a different matter: `install.sh` fetches the rule sets for
Hayabusa and Chainsaw at install time (Chainsaw's include its $MFT rules),
under their own directories (`hayabusa.status` says where). Adding such
rules follows those tools' conventions, not `rules/`.
