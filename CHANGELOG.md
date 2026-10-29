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
changes (1.1.0), the first for a major release. The update's commit
moves the Unreleased lines under a heading for the new version.

## Unreleased

## 1.0.2 — 2026-10-29

Providers and profiles:

- Provider profiles: what Atlas knows about each LLM provider type (base URL, the header the key goes in,
  static headers, how a thinking level is spelled and which levels it takes, reply fields sent back, whether
  a temperature is refused) is one file per provider under `provider_profiles/`, no longer code. Your own
  profiles go in `provider_profiles.local/` (ignored by git; `ATLAS_PROVIDER_PROFILES_DIR` names another
  folder): a file there changes only what it names in the shipped profile of the same id, or adds a
  provider. A file that fails its checks makes the providers bound to it unusable with the file, the key
  and the reason, shown by `atlas doctor`, Test connection and the start of a run; it is never replaced by
  the shipped one. A user file for the fallback profile `custom` is not read (doctor says so), so the
  providers that bind to it keep working. The wire formats (OpenAI Chat Completions and Responses) and auth
  schemes stay code.
- New provider profiles: Groq, Together AI, Fireworks AI, Cerebras, Azure OpenAI (v1 API, key in the
  `api-key` header), LM Studio, vLLM and the llama.cpp server.
- A provider binds to its profile by `ATLAS_PROVIDER_<NAME>_PRESET`, else by its name in any letter case
  (before, only the exact lower-case id matched): a provider named `OpenRouter` now gets OpenRouter's request
  shape. A `_PRESET` that names no profile makes the provider unusable with the reason (before, it was
  ignored). Setup and the settings page now record the profile for every provider they save. A provider is
  never matched to a profile by its host. One registered as "Other" at api.anthropic.com therefore no longer
  gets the `anthropic-version` header on its model list; `atlas doctor` names the
  `ATLAS_PROVIDER_<NAME>_PRESET=anthropic` setting that binds it.
- Anthropic runs on Anthropic's own Messages API with prompt caching: the `anthropic` profile sends its calls
  to `/v1/messages` with the key in `x-api-key`, and marks three 5-minute cache entries (the system prompt
  with the tool list, the case brief, the history up to the last tool result), so a turn pays the full input
  price only for what is new. A thinking level goes out as `output_config.effort` (low to max; minimal and
  none are sent as low, and no thinking switch is sent); Claude Haiku 4.5 and Sonnet 4.5 get no level, and
  Opus 4.6 to 4.8 and Sonnet 4.6 run without thinking on this profile. Forced tool use is sent as auto on the
  models that refuse it. A provider saved with `_PRESET=anthropic` uses the Messages API from its next call
  on. The OpenAI-compatible layer stays selectable as "Anthropic (OpenAI-compatible layer)"
  (`_PRESET=anthropic-compat`); it no longer gets a thinking budget, which current Claude models refuse.
- Anthropic can be saved as a provider: the connection test, `atlas doctor --probe`, `atlas provider use` and
  `atlas models` send the `anthropic-version` header Anthropic's model list requires. For every provider, a
  save from the dashboard is now refused only when the model list does not vouch for the model and the model
  does not answer either: such a save runs the Test connection calls (up to three short model calls) before it
  is refused or written. Before, a provider whose model list failed or left the model out could not be saved
  without skipping the test. The CLI wizard is unchanged. The Anthropic (OpenAI-compatible) profile sends
  `anthropic-version` on every request, its chat calls included; before, only the model list carried it.
- Fix: the setup wizard's connection test and the settings page's Test connection use the chosen profile's
  auth header; before, they always sent `Authorization: Bearer`.
- `atlas doctor` lists where the provider profiles come from, the ones that cannot be used, and the profile
  each provider binds to; doctor and `atlas provider test` show where each base URL comes from (a variable,
  or a shipped, user or merged profile file).
- A model list that comes in pages is read to its end wherever Atlas reads it: the context probe, `atlas models`,
  `atlas doctor --probe`, `atlas provider use` and Test connection. Anthropic's list (20 a page unless asked)
  is asked for up to 1,000 a page and followed while it has more, so a model past the first page is no longer
  "unknown" and a run set to it no longer stops. A provider profile names the paging style
  (`[connection] models_paging`).
- The model context probe reads each model's full window: it sends the provider's own headers, so Anthropic's
  model list answers, and it reads a field that states the window (`max_input_tokens` and the like) before
  `max_tokens`, which next to one is the output cap. Claude Sonnet 5.5 and Haiku 5.5 now get their 1,000,000
  token windows instead of the 128,000 fallback, so a Claude run keeps up to about 750,000 tokens of history
  before older turns are shortened: more context per call, and more input tokens per call (on Claude Haiku 5.5
  a prompt over 100,000 tokens is billed at its higher price, which the price list now prices). Mistral's
  window (`max_context_length`) is read too, and a model set by its alias matches its newest dated snapshot in
  the list (Anthropic lists `claude-haiku-4-5-20251001` for `claude-haiku-4-5`), so a run set to the alias is
  not stopped as an unknown model now that the list answers.
- Atlas's own input pacing (`ATLAS_AGENT_INPUT_TPM`) counts what the provider's rate limit counts. A provider
  profile can say its input-tokens-per-minute limit leaves cache reads out (`rate_limit_counts_cache_reads =
  false`); the Anthropic profile does, as Anthropic counts only uncached input and cache writes. A Claude run
  with a long, cached history is no longer slowed to about one call per minute. Every other provider counts
  all input tokens, as before.
- When a provider refuses a completion limit above its maximum for the model and names that maximum
  (Anthropic: "max_tokens: 65536 > 64000, which is the maximum allowed ..."; OpenAI: "supports at most N
  completion tokens"), the request is sent again with the maximum and the model's limit is remembered.
  Claude Haiku 4.5 therefore works on the native Anthropic profile.
- When the model provider's safety classifiers decline a request (Anthropic's `refusal` stop reason, a
  `content_filter` finish elsewhere), the turn ends without a retry: the run's trace shows the category and
  the explanation the provider gave, the token ledger records the call as `refused`, and partial output is
  dropped. The next request tells the model in one line that the provider declined and asks for another
  approach; three declines in a row end the run (stop reason `model_refusal`). The chat shows the decline
  where the answer would have appeared, and a work item of the frontier loop ends.
- Fix: a call to a Claude model no longer rewrites the conversation it was sent. The prompt-cache markers go
  on copies, so a session saved with `/save` and a later call to another provider carry the plain messages;
  the request a Claude model gets is unchanged.
- Fix: an HTTP 529 from the model provider (overloaded; Anthropic's `overloaded_error`) is retried with the
  backoff a 503 gets, and one that outlasts the retries is a lost turn the run asks again. Before, a single 529
  stopped the analyst's run with an LLM error.
- A provider that answers "rate limited" without saying how long to wait
  is now asked again after 2, 4, 8, 16 and then 30 seconds instead of every
  2 seconds; a stated wait still wins.
- `ATLAS_PROVIDER_PROFILES_DIR` expands `~`, and a relative folder is taken under the Atlas folder. Before,
  `~/profiles` named a folder called `~` under the current directory, and a relative folder depended on where
  Atlas was started; in both cases your profiles were silently not read.
- A provider whose profile takes no key (a local server) is ready without one: runs, the reviewer, `atlas models`
  and the Settings page no longer ask for a key it does not use.
- Provider settings and keys with a line break or another control character are refused before `.env` is written,
  so a pasted value can no longer add a line to it.
- Two provider names that would share their `.env` settings (`gw-a` and `gw_a`) are refused on save; an existing
  pair is reported unusable, each naming the other.
- Saving a provider checks its model list and makes no model call. A model the list does not show saves after
  Test connection got an answer from it; one typed in another letter case is stored as the list spells it.
- A save that names no known provider profile is refused with the known ones, and the chosen profile is
  remembered also for a provider named like it.
- A provider can be pinned only to a thinking level its profile lists (Z.ai: low or high; Mistral: high). The
  wizard and Settings offer those, and `atlas doctor` names a stored level the profile does not take.
- Test connection waits for a thinking model, with a Cancel button, instead of giving up after 15 seconds. A
  provider that gives no answer at all is reported at once, and the whole check ends after 90 seconds.
- Removing a provider deletes all its settings, its key in the keyring and what Atlas learned about it; `atlas
  doctor` lists settings an earlier removal left behind.
- Settings shows the chosen profile's description and notes. Other has Auth header and Auth prefix fields, and
  the wizard asks for them.
- `atlas provider profile init <id>` copies a shipped provider profile into your folder to edit;
  `atlas provider profile path` shows the folders. Every shipped profile explains its keys.

Model calls, retries and cost:

- An analysis run on a Claude model with a 1M-token window lists every Atlas tool from its first turn, and the
  list never changes during the run. Before, the list held at most 128 tools and swapped namespaces in and out,
  and every swap made Anthropic write the whole prompt to its cache again at the cache-write price. A provider profile
  says how many tools a request may carry (`[request] max_tools`, set for Anthropic); the window bounds it, so
  a 200K-window model keeps 128, and a chat keeps today's switching list. The run's stderr names the mode
  (`atlas: tool list: ...`).
- The tool schema array stays the same between requests unless the model loads a namespace: a
  preload for the director only fills free room, and namespaces are listed in the order they were
  loaded, so a provider's prompt cache keeps the conversation. Switch ATLAS_TOOL_ARRAY_STABLE.
- A model call the provider or the connection cuts no longer ends or wraps
  up a run that has had a reply: the analyst's turn is asked again after a
  pause (60 s doubling to 5 min), one thinking level lower, then as a short
  progress question without tools over the full and then a shortened
  history, and the run carries on by itself when the provider answers. A
  provider error event inside a stream counts as a failure, not as the
  model's reply. A run whose provider never answered stops with the error
  after two re-asks. The run log shows every loss and every recovery, even
  in quiet mode; the dashboard card shows what the run does next and, past
  ATLAS_ESCAPE_ALERT_SECONDS (default 30 min), an alert.
  ATLAS_MODEL_CALL_ESCAPE=0 restores the earlier retries and wrap-up.
- A refused tool_choice value ("required" on some endpoints) is remembered
  for the model instead of dropping the parameter; "none" keeps working
  (ATLAS_TOOL_CHOICE_VALUE_MEMORY).
- The starvation ladder no longer climbs from a reply asked at thinking level
  "none" (or "minimal"): no lower level exists there.
- The orchestrator's model re-ranking of evidence files runs only when
  ATLAS_ORCH_LLM_RANK asks for it, under its own role; it used to run under
  the analyst's role every fifth turn, and a starved call could teach the
  thinking ladder a lower level for the analyst. The ladder now remembers
  a thinking level only for the role that asked; a helper call without a
  role runs at the analyst's level and changes nothing.
- The belief-starvation message stands once instead of once per latched
  turn (ATLAS_REFUSAL_ACCOUNTING).
- Every single-answer model call (the answer composer, the question
  planner, the director, the reason tools, the reviewers, the report
  sections) is asked under an output allowance of 64,000 tokens: a reply
  that runs past it is asked again once at a lower thinking level and then
  falls back, so one runaway reply can no longer burn a whole completion
  window. Switch ATLAS_ONE_ANSWER_ALLOWANCE, size ATLAS_ONE_ANSWER_MAX_TOKENS.
- After a stuck model call is answered with a progress summary, the next
  ask names the work order's first due read as the call to make, when the
  work order is on and a read is due.
- A tool call repeated with the same arguments inside one model reply is
  answered "duplicate of call N in this reply, not run" instead of running
  again; more than five such repeats mark the reply a runaway and the next
  ask goes one thinking level lower (ATLAS_REPLY_DUPLICATES).
- A streamed tool call whose arguments arrive as an object, under `parameters` or on the call itself is taken
  as the whole arguments until a complete object has arrived. A call that arrives with no arguments is logged
  with its raw arguments and the provider, and a call to a tool with required arguments that carried none is
  told the fields it needs in one line.
- A helper request (a reason tool, the answer composer, the question planner) whose reply was cut, by the
  one-answer allowance or by the provider, is not sent again unchanged in the same run until a later call of
  that tool answers; the skipped call returns an unusable result. An empty conclusion after a finished reply
  is asked again. A helper role opens at the lower thinking level that answered after a cut, and a role whose
  lower level was cut too is not asked again. This memory is cleared at each run start.
- A helper that gives no usable answer to three requests in a row turns a missing question plan or synthesis
  from a blocker into a documented limitation, so the pre-report check can be ready; the report prints the
  limitation and how many requests reached the model. The run's finish status still reads the missing
  synthesis and stays not complete.
- Token spend is labelled USD by default, the currency vendors publish their prices in. The label converts
  nothing; it can still be changed under Settings.
- Token spend counts the tokens written to a provider's prompt cache apart: the usage ledger has a column for
  them (an existing ledger gains it on first use, its earlier rows at 0), the price list a "Cache write" price
  (empty: the input price), and the usage page and the CSV export (new last column `cache_write_tokens`) show
  them. Before, cache writes were billed at the input price, which understated a Claude run's cost.
- The price list takes a second set of prices for long prompts (under *Long prompts*: the prompt length they
  start above, and input, cache read, cache write and output). Each request over that length is priced at
  them, its cache reads and writes counted towards the length, as Anthropic bills Claude Haiku 5.5 over
  100,000 prompt tokens. The price list's "Cached input" column is now "Cache read".
- The usage page and its CSV count requests lost to a cut stream in their
  own column (no tokens, no cost).
- Fix: a rerun's model calls are no longer counted twice on the usage page. The investigator's transcript is
  named after the run id the rerun records its calls under, so the history import knows the run; an agent
  started by another Atlas process no longer records under that process's run.

Reading evidence:

- Disk containers (VMDK, VHD, VHDX, QCOW2, VDI) are read without a copy: each gets a read-only raw view
  (qemu-storage-daemon over FUSE, no root) at `mnt/<image>/disk`, which the contents index, the Sleuth Kit
  tools and plaso read, so a case of many images needs no free space for copies and a renamed VMDK opens.
  A container that names a file outside its folder or a network location, or whose parent qemu does not
  apply (a differencing VHD or VDI, a VMDK delta without its parent or made on a changed parent), is
  refused with the reason; a snapshot base is an earlier state, read on demand. Without FUSE the copy
  (`img_vmdk_export_raw`) stays, now keeping the case volume's free-space floor; it is refused while a view
  serves the disk. A tool run as root is refused on a view; the run-end teardown stops the views except the
  ones a running background job reads. `ATLAS_RAW_VIEWS=0` switches the views off: the readers then take the
  container as it is (the route texts still name `tsk.mmls` first).
- A file inside a disk image is read in one call: a parser given an image
  handle `<image>::<path>` (from `tsk.index_find` or the host view) gets
  the file extracted first, the result says which copy it read and which
  call extracted it, and the parse's trace entry names that extraction.
  The texts that frame the evidence now say that exports are an index of
  what the images hold and the images the authority. Switches
  ATLAS_IMAGE_HANDLES (follows ATLAS_DAIR_NO_DEFER) and
  ATLAS_EVIDENCE_FRAMING.
- Reading a folder extracted from a disk image (an image handle on a directory, or a batch extract of one) no
  longer stalls the turn while the index ties every file of the copy to its listing: the lookup now runs on
  the index the listing already has (host and path) instead of walking every row of the image per file, and
  the copies go in with one write. The time this took grew with the size of the listing times the number of
  files in the folder; it now grows with the number of files alone. The per-file registration of a batch
  extract's single files is unchanged (one write per file) and queued.
- `job_start_image_extract(images, paths, dest)` copies one path, glob or folder from several disk
  images (or all of them) as one background job, resolved through the contents index; the collect
  names the folder, the copies and each failure, and ties every copy to the file it came from, so one
  parser call over the folder reads them all. Switch ATLAS_IMAGE_EXTRACT_JOB.
- Atlas lists every disk image of the case once at intake (a contents
  index): the director and the analyst see, host by host, which high-value
  files inside the images no call has read, the hosts the questions and the
  brief name first; `tsk.index_find` finds a file inside any image without
  running fls; the Evidence Gaps group the unread files by class, name each
  listed host nothing inside was read on and each image that could not be
  listed with its reason. An absence claim or a "source absent" limitation
  is checked against the host it names. Switches ATLAS_CONTENTS_INDEX,
  ATLAS_INDEX_HOST_VIEW, ATLAS_COPY_PROVENANCE, ATLAS_INDEX_STATUS.
- The analyst is shown what the images hold, one line per host (file count, commonest extensions, the
  largest directory trees few other hosts hold), once after the inventory and again after compaction;
  an index search with more matches than its limit returns one line per directory, and a listing cut
  at the output cap returns the summary of the whole listing. Switch ATLAS_LISTING_SHAPE.
- The per-question plan sees what each host's image holds: a first call names up to four places to look
  (host and path glob), and the plan is shown what the contents index holds there, one line per
  directory with a handle. Switch ATLAS_PLAN_LISTING.
- Event logs, mail stores and captures the contents index lists inside the case's images count as
  present in the evidence profile and the inventory result ("N files inside M hosts' images"), never as
  absent. Switch ATLAS_PROFILE_INSIDE_IMAGES.
- A file named with its host joined by a hyphen (corp-ws01-triage.raw) is mapped to that host: one
  path-to-host matcher reads the Evidence Links first, then the host label as a token, the longest label
  winning; the question planner, pivots, image lookup, export and listing hosts use it. Switch
  ATLAS_HOST_OF_PATH.
- Each export's coverage is profiled (rows, time span, hosts, parser kinds, event-log channels with
  their event ids, and per host the log and text directories of the image it did not parse):
  `inventory_evidence` lists it, the host view names what the exports skipped, the run status and the
  evidence table count the high-value files read inside each image. An absence resting on an export
  counts only for the channels and event ids its profile shows, and an absence about a host whose
  listed image holds unread files the sentence names is refused with an example and its handle. The
  intake listing records each listed image as opened. Switches ATLAS_EXPORT_PROFILE,
  ATLAS_INDEX_OPENS_MEDIA (and ATLAS_ABSENCE_GATE_V2 for the gate).
- A disk image counts as opened once a file inside it was read
  (tsk.resolve_path, tsk.icat); a failed read inside an image no longer
  marks it failed, and a directory holding several images no longer names
  one host's image in the absence check (ATLAS_ABSENCE_GATE_V2).
- A row's source becomes a read only when the case holds it on the row's host; other sources are
  disclosed once as not found among the case's files or listed images. Switch ATLAS_SOURCE_IN_CASE.
- A directory's files are ranked for an input-scale refusal and the plan by the words of the focus
  text they hold, then by name; the refusal states the total and names the listing that pages
  through the rest. Switch ATLAS_SHARD_ORDER_NEUTRAL.
- A strings pass, text grep or text read over an input whose format has an installed parser (a hive, a
  Prefetch folder, an event log ...) is refused with the parsers named, for planned reads and the
  analyst's calls alike. Switch ATLAS_FORMAT_READER_ROUTING.
- The director's review and the analyst's tool guidance carry a "readers by input format" block read
  from the tools' declared input parameters (which tool parses an event log, a hive, a Prefetch
  file, a mail store...), so a parser is chosen over a text search. Switch ATLAS_READERS_BY_FORMAT.
- A tool's parameter lines are sent as its parameters' descriptions and its description stays
  under the 1,024-character bound, cut at a paragraph or sentence; four long docstrings were
  rewritten so nothing the model needs is cut. Switch ATLAS_TOOL_PARAM_DESCRIPTIONS.
- A tool declares the media types it reads in its own registration. The reader table the analyst and the
  director read follows those declarations and the content type found by libmagic, so carved pictures,
  documents and archives name a reader, and the finish's class lines name up to three installed readers, one
  per namespace. Names taken from the evidence are quoted and capped.
- A planned read of an image handle stands where a read of it would run, judged against the image's complete
  listing, and a planned read into an image with no host link is checked against the image's own listing. A
  read whose tool takes no string input is refused, and a reader of another reader's output is judged by its
  producers' declared input.
- A whole-image read by a reader whose input is one file of the image's filesystem (the MFT, the change
  journal, shortcut, prefetch and jump-list files) names that file when the image's listing holds exactly one
  live file of that name on one volume, stands as named when it holds several, and is not made when the
  complete listing of every volume holds no file of that name, deleted ones included.
- A Sleuth Kit `icat` call without `-o` names the entry at sector 0 (the filesystem of an image with no
  partition table). A file `icat` wrote is registered as a copy of the entry it read when it is in the case
  and has the entry's size, with its sha256, so the read item closes.
- A Sleuth Kit call with a metadata address that does not belong to the image
  (taken from a timeline, another image or another copy of the volume) now
  says so and points to finding the file by its path.
- Times written to the minute ("2031-03-10 14:02") and slashed year-first times are read as moments; a
  "09:00-10:30" span is no longer misread as a time zone offset.

Tables and searches:

- The table tools take one period (`time_start`, `time_end`), page through matches in time order (`offset`,
  `order="desc"` for newest first) and write every matching row to a file (`output_csv` on `table_grep`);
  `table_query` sorts a time column by its parsed time; `table_schema` names the time columns and their span;
  the hints that say how to see the rest name one period and one term (paging and the file of every row stay
  parameters but are not offered). Switch ATLAS_TABLE_TIME_ARGS. The `output_csv` parameter of `table_query`
  and `table_grep` now says only that it writes every matching row to a CSV under analysis/ or exports/; it no
  longer tells the model to use it when the matches exceed the return cap.
- table.table_grep counts every match of the file: the number of matching rows, per term its rows and first
  and last time, the sources and the days the matches fall on. When more rows match than max_hits, the rows
  returned are a survey of all of them (the first row of each term and of each source, the last row of each
  term, the rest spread over time) instead of the first rows of the file. A large match set is counted in one
  streamed pass, by line, and the result says so. table.table_query does the same for a filter without offset,
  sort_by or output_csv. The new sources argument counts the same pattern in other tables, without rows.
  ATLAS_TABLE_SURVEY=0 restores the search that stops at its cap; ATLAS_TABLE_FULL_PARSE_LINES (default 20000)
  sets where the streamed pass begins. A search pattern holding a Windows path (an escaped backslash) takes
  the fast grep path instead of the row loop (ATLAS_GREP_GUARD_TOKENS).
- Fix: a `table_query` that returns fewer rows than match (with a period, `sort_by` or `offset`) no longer
  reads as complete. Its result carries `hit_cap_reached` on every path, and what the model reads says
  "N of M matching rows", which run of them came back, and the calls that reach the rest: one period, a
  narrower `where=`, a count of every match by a column with `table_pivot`.
- A table search for several alternatives that stops at its hit limit now
  says which alternatives match a row anywhere in the file and which match
  none, so one search settles every indicator it names; before, one frequent
  term filled the limit and the reminder asked for the same search again and
  again. On a plain-text table the rest of the file is read by grep, in
  seconds instead of minutes.
- table.table_pivot stacks: over a glob or list of tables (each under its host), the contents index or a
  prior call's output, order="rare" lists the values fewest hosts hold first, with their hosts, rows and
  first and last time. Several tables are counted in one native pass each (gawk, now installed by
  install.sh). Switch ATLAS_STACK.
- The event-log dump and filter stop at a per-call deadline (at least the default timeout, more for a
  large log) and return how far they read, the time the rest would take, and a `resume_from` that
  continues in file order; the dump appends to the same output file. For these two tools the bulk
  repeat gate keys on what a call reads and writes, so a repeat that differs only in a budget or
  display size is refused; other bulk tools keep the full-argument key for now. Switches ATLAS_INPROCESS_DEADLINE and ATLAS_REPEAT_KEY_PATHS.
- The estate count: the brief's indicators are counted across every table once the inventory is done, again on
  every new table and for indicators the findings add; the counts (rows per host, first and last time) open
  the work-order block and replace the owed searches of the pivot nudge; Evidence Gaps lists rows counted but
  never shown; the IOC tab shows the counts (ATLAS_ESTATE_COUNT). It reads each timeline in one pass of grep
  for every indicator at once and runs beside the analyst's turns: the work order says it is counting until
  the counts arrive (ATLAS_ESTATE_COUNT_NATIVE and ATLAS_ESTATE_COUNT_ASYNC). Several new tables in one turn
  are counted in one pass, not one thread and trace entry per table.

Coverage and open work:

- The coverage ledger records every handed-over evidence item and the content classes inside it, each
  with a disposition (pending, relevant, read, partial, left) and its reason and proof; a pending unit
  is never counted as touched, and a unit marked blocked in the model's words is triaged again. Switch
  ATLAS_EVIDENCE_DISPOSITION.
- Coverage honesty: a listing of an image is recorded apart from a read
  of its content; the report's evidence table says "read", "listed only"
  or "not examined", Evidence Gaps names every image only listed, and the
  coverage floor and the access stage are report warnings instead of
  blockers at a question's close, at Report entry and in the pre-report
  check (ATLAS_COVERAGE_HONESTY).
- The report no longer lists a registry hive, event log, Prefetch or jump-list folder on a mounted image as
  "Not opened" when a call read it through the mount, and a file whose folder was given to a parser that
  failed stays "Not opened" with that failed call named, instead of "no read was attempted". A mail store a
  call read now counts toward its class in "Evidence not analysed".
- The report's Evidence Gaps no longer say "no file inside it was read" about an image the run did read: the
  line now asks the trace's read rule (a read of the image, or an extraction from it, credits the image), not
  whether a high-value item of the image's host was read. "Evidence not analysed" no longer lists a capture
  or single file the run read in full as "no content classes known (read)".
- The report waits while the case lists high-value artifacts nobody has read
  (event logs, registry hives, Prefetch and the like): each is read, its read
  fails, or the run states why it is not read ("UNRESOLVABLE: <artifact> —
  <why>"). A run that does none of these still reaches its report when the
  report phase winds up, and the report's Evidence Gaps section lists every
  high-value artifact it did not read, with the reason given, the read that
  failed, or a note that no reason was recorded.
- A file named in a case question is no longer lifted above every other
  unread artifact; it ranks by its kind like any other file.
- The work order: the reads a run owes are kept in the trace as work items
  and shown every turn, last, as ready calls (up to six). An item closes
  when a call reads its target or fails to; a question answered or dropped
  makes its planned reads moot. The report push, the first atlas_finish,
  the stall ladder's force-report and the gate-ready close-out wait for
  due items until they are read or the order is neglected (shown for
  ATLAS_AGENT_REPORT_STALL_TURNS turns without a read); the report lists
  every planned read not done. ATLAS_WORK_ORDER=0 restores today's run.
  The order is filled by a plan per question once the inventory is done
  (one reason-role call each, with the hosts and dated sentences of the
  brief's narrative; ATLAS_WORK_ORDER_PLAN), by the director's reads, by
  the file behind the timeline rows a question's claims rest on
  (ATLAS_WORK_ORDER_SOURCES) and by absence claims the case index
  contradicts; unread index artefacts and partly read series reach the
  director as proposals. The director is asked for a review when the due
  reads run out, the order is neglected, a re-plan adds nothing or a
  question closes or reopens; its ritual orders are no longer inserted.
- The director reviews the work order instead of planning batches: it reads every question with its
  items and claims, what each claim rests on, the due, failed and proposed reads and the findings
  since its last review, and answers with work items, adopted proposals (with a target) and
  dismissals that name the call that already read the target. Switch ATLAS_DIRECTOR_REVIEW (with
  ATLAS_WORK_ORDER).
- The work order no longer carries items nothing can close. A director entry that is a tool name alone, or a
  host alone, made a "proposed" item with no target; no read could close it, the director could not dismiss
  it, and a promote without a target made it a due item that held the run and was shown every turn. Such an
  entry now makes no item: the next review lists it as refused ("no closable target ...; not tracked as
  work"), the director line counts it, and a promote that leaves no target is refused with the two ways to
  give one, or keep. A run's open-work count is therefore not comparable with runs before this change: the
  director proposals without a target (one per bare tool name the director listed) no longer exist, nor the
  due item a target-less promote made.
- Under the work order a run is `complete` when it has beliefs, the report, a synthesis, a ready
  pre-report check, no actionable question and no due read; the coverage ledger's unseen units,
  its floor and the unmet obligations are recorded beside the label (`coverage_disclosure`).
- The director's principal candidates are the accounts its tool summary names that the case does not
  know yet (cue `unseen`), the rule host candidates follow; no logon or creation vocabulary decides
  them. Switch ATLAS_DAIR_PRINCIPAL_UNSEEN (with the scenario report checks off).
- A read cut by a time bound (a deadline, an executor timeout) blocks finish until it is resumed,
  replaced by a read of the same input or dispositioned, whatever its topic; the auth-scan topic
  debt and the display cut of a named tool's output no longer block the report or finish. Switch
  ATLAS_INCOMPLETE_READ_DEBT.
- No deferral: the DAIR window no longer blocks forensic tools, a resumed run's waiting intents are retired,
  and a [progress] line every 20 actions replaces the window warning; dair_required and hypothesize_required
  no longer refuse a finding (ATLAS_DAIR_NO_DEFER). A tool call blocked by the director protocol (the DAIR
  window, the deferred backlog) no longer counts as a search of its indicators or a read of its evidence.
- Fix: the evidence-disposition checks that look for an attacker value or a host's account in other hosts'
  exports passed bare values to the export count, which counts only typed indicators, so they never found a
  hit. Bare values now get their form (a path by its full value and last component, anything else as
  written) before the count.
- The finish names one list of open work (open question parts, unread extracted classes, due reads) with a
  next step on each line, and the unread classes return each turn as the last block until none is open. A
  projected report that later findings postdate is projected again at every ending. The director is no longer
  told a repeat rate it counted wrongly.
- An extracted class no call read is left only by a fact the code recomputes from the trace and the file
  system (every reader the tool declares for it is installed and failed on two distinct files, or every file
  is empty), never by the model's own verb.
- One reader decides what a call read: the coverage ledger, the extracted outputs, the contents index items,
  the evidence items and the work order all credit through it, and a call over a folder no longer counts as
  reading every copy below it. Output files a parser processed and nobody looked at are a state of their own,
  parsed, shown as open with a next step in the finish's open-work list, the report's evidence not analysed
  and the Coverage tab; the finish defers once for them.
- Reads the run really makes are credited: a mount the access plan made is one of an image's readable forms (a
  mounted filesystem shows live entries only, and the volume the auto-mount chose is recorded beside the
  mount); a path parameter's value is one path, spaces included, and an image handle may hold spaces; a
  full-volume listing's rows tie to the image's entries within the volume the listing was parsed from; three
  tools named like listings (device install inventory, HTTP session inventory, tcpdump connection list) read
  content; a folder parse by LECmd, JLECmd or RBCmd stamps the files its own report names as processed, and a
  class parsed into no output file gets its own reason and report line.
- A collected tree's or a loose file's content classes are credited by the reads of their own files: read when
  a successful content read named every file the class was built from, partial with its count when some were,
  parsed when only a parser's report named them. A partial class moves on with its reads, an image class too.
  The wiring parts of an unpacked Office Open XML package (content types, relationships) are package
  structure: never offered, and a read of them reads no content. The package reader opens only regular files,
  never a FIFO, a device or a link out of the extracted unit.
- The contents index no longer scores a folder as a file of the same name: a folder named like a registry
  hive, a browser history or an SRUM database took that artifact's class and stayed an open high-value item. A
  directory now scores only for the folder entries the artifact table lists (the Prefetch folder, jump-list
  destinations, burn staging and the like), and an index directory's own size no longer marks it empty.
  Existing indexes are rescored once.
- Carved pictures are described by a vision-capable model when the brief turns it on (a brief row that fails
  closed). The gaps name each extracted picture class no model can identify by its content, with its file
  count and the reason the vision tool gives (descriptions off in the brief, no vision model, a model that
  takes no image); nothing under a handling stop. The steganography negative states that jpseek reads the
  Linux 0.3 format only and names the manual route. The run record names the vision role's model only when the
  describe tool would use one.

Questions and answers:

- A question's answer leads with the beliefs the analyst bound to its parts;
  a finding recorded during the run no longer closes the parts it would
  answer, so a question is closed only by the analyst's own update. Before,
  the first belief with a value of the right type closed a part, and the
  printed answer followed the task's links alone. A question the analyst
  never closed now prints its related findings instead of a lead the
  auto-close picked, and a status-only progress note on a question no
  longer closes its parts from the links a finding made.
- Each answer to the case's questions is led by the finding or conclusion
  about that question: a strong conclusion no longer leads every answer it
  shares a word with, and words found in most findings (the organisation's
  name, the domain in account names) no longer count as a match. An answered
  or partly answered question is led by its own conclusion when that is closer
  to it than the findings it was closed with, so a refused close no longer
  leaves its answer on older findings.
- Parts of a question with no words of their own ("why", "how", "for each")
  can be answered: they are judged against the question's text, and a finding
  linked to the part answers it through any of its sentences. "Which accounts
  were used for lateral movement" is judged on "lateral movement", so it is
  no longer answered by an account used for something else.
- A request part that names a file class ("an executable") is answered with a value of that class wherever
  the belief states it, also when the analyst names the belief for the part: a picture in the first clause no
  longer stands in for the executable named in the second.
- A question part closes on the structure of the beliefs the analyst names for it in that call, never
  on stored links or on words; the answer composer may state that a linked belief does not answer a
  part (traced for the reviewer); an absence answers a yes/no part only over the hosts it asks about.
  Switch ATLAS_PART_GATE_STRUCTURAL.
- A question part may name what its answer ranges over (one row per host, account, file, endpoint or
  event); the plan call declares it, code fills the rows from the findings, and the answer names the rows
  still open. Switch ATLAS_MAP_VIEWS.
- `update_investigation_task` takes one part through flat parameters (`part`, `part_claim_ids`, or
  `limitation_basis` with its allowed values in the schema, `limitation_reason`, `limitation_call_ids`);
  the `parts` object stays for several parts. Switch ATLAS_PARTS_FLAT_ARGS.
- A composed answer can say what the work order read or failed to read for its question (READS lines)
  and what the evidence shows of each value its beliefs name (VALUES lines: sightings, no sighting,
  shared infrastructure); the report prints such a citation as the read's item or the indicator
  list. Switch ATLAS_ANSWER_READS_VALUES.
- The report's answers are written per question by one model call over the
  findings that speak to it: every sentence ends with the finding ids it
  rests on, and every host, account, file, address, time and number in it
  is checked against those findings (one repair round). An answer that does
  not pass prints the earlier text with a marked line under it. A question
  never closed carries "open" in its heading; the pill is the lowest tier of
  the findings the first sentence cites; findings the analyst did not link
  are listed as "Also cited". ATLAS_ANSWER_COMPOSE=0 restores the earlier
  answers.
- Closing an answered task no longer suggests promoting a conclusion while
  the answers are composed.
- The run status record carries the last report's answer counts
  (composed, cached, fallback with reasons).
- A composed answer quotes text taken from the evidence: the prompt asks
  for it, and a run of eight or more words copied from a cited belief's
  evidence is put inside quotation marks when the answer did not, so an
  instruction-shaped string in the evidence never reads as the report's
  own words (the trace records each such run).
- The composer's sheet, parser, check and prompt agree on what they name: a part the sheet does not list is
  named neither on a linked belief's note nor on a view's rows, a dated clock range is a range and never a
  clock with an offset, the sheet's own line and part ids written in a sentence are ids and not names, and a
  failed composition traces the failing sentences per round. A sheet that lists no part gets rules with no
  part mechanics, so a model copies no part id into an answer whose check refuses it; a sheet with parts keeps
  the full rules.
- Each value line of the answer sheet says what was checked: a shape refused at record time was never checked
  against tool output, a presence refusal that a later call shows names those calls, and a kept row without
  sightings is shown by its cited calls. The label "no sighting in any tool output" is no longer put on values
  that were seen later or kept without a sighting, and the lines a reply must not state as seen come first.

Findings and the gates:

- A finding that states something about every row, or an absence, over a
  result the analyst saw only in part is refused without a suggested
  rewording: the refusal names each such sentence and asks for the count
  first. A recommendation over every item ("reset every account") is
  routed to claim.add_recommendation instead of being reworded into a
  finding (ATLAS_UNIVERSAL_GATE_V2).
- A malware family name is accepted only when a cited tool output prints
  it: a shipped or installed rule match, capa, clamscan or a cited lookup
  result; a rule the analyst wrote never grounds it, and protocol words
  ("SMB beacon") are no longer read as part of a name. The refusal leads
  with the scan or lookup to run. A LIKELY finding that binds an account
  or an act to a person is evaluated adversarially; a challenged one is
  recorded as SUSPECTED with the evaluator's reason and the read that
  would raise it (ATLAS_EXTERNAL_LOOKUP_FIRST).
- An attribution verdict at CONFIRMED or LIKELY (an account bound to a person, or a person named as
  the actor) passes when a call it cites prints the credited account or person in a row beside
  another term of the claim; a person matches the account spellings of their full name. The
  refusal lists the trace calls whose rows show that and names no record type. Switch
  ATLAS_ATTRIBUTION_IDENTITY_ROWS (acts with the LIKELY attribution evaluation).
- A conclusion names the claims it rests on (`claim.promote_conclusion(basis_ids=...)`): every name it
  states must stand in a basis (the refusal says which claim states it, or which call shows it), an
  absence covers only the hosts its bases' complete searches read, a reworded conclusion meets the
  statement gates, and its tier is never stronger than its weakest basis, re-applied whenever a basis
  is revised or withdrawn. Switch ATLAS_CONCLUSION_DOOR.
- A quotation from a cited tool output is checked against that output
  however long ago it ran (ATLAS_QUOTE_GATE_CITED_BY_ID).
- The earlier citation repair, the citation blocker with its hint and streak, and the lowering of miscited
  findings stay available behind ATLAS_LINEAGE_WIRING=0 and ATLAS_CITATION_DISCLOSURE=0. They are removed
  together with those switches in a later version.
- Two findings recorded for one event are folded into one when a later finding shows the identifiers
  of both: the second is superseded by the first and its citations are carried. Switch
  ATLAS_TWIN_FOLD.
- An indicator typed account whose value is a program or script file name is refused ("type it as
  file"); a qualified account may hold spaces (NT AUTHORITY\SYSTEM). Switch ATLAS_ACCOUNT_SHAPE.
- A host or account indicator may state attacker_from, when the attacker first acted on that host or
  with that account (checked against the cited output). A finding that leads with an earlier time gets a
  window_note asking why the row is the attacker's; the answer composer sees a WINDOW block, the
  beliefs that precede it are flagged, and the account sets frame who acted. Never a refusal. Switch
  ATLAS_WINDOW_NOTES.
- The recording nudge names the reads whose rows no finding cites yet, by call id, file and rows shown, while
  their results are still in the conversation (three such reads over two turns place it, at most eight named,
  oldest first), and asks, before the next reads, for one finding per thing a read showed that bears on the
  case; routine or baseline activity is not a finding. An accepted finding citing a read takes it off the
  list; a note does not; a read that showed only routine rows leaves on its own. It replaces the count of
  reads since the last finding and the work-order block's own record line. `record_finding` no longer returns
  a volume advisory when findings outnumber the case's questions, and the playbook no longer tells the model
  to record fewer findings.
- The grader (the ground-truth comparison) is never offered to the analyst, and no tool is exempt
  from the answer-key gate while it is hidden. Switch ATLAS_HIDE_GRADER.
- A CONFIRMED finding stands only when a cited call's row shows every checkable entity, minute time and
  quotation it states; otherwise it is recorded LIKELY with no evaluation spent. The adversarial evaluation
  reads the matching rows of the cited calls.
- A record's own fields beside the records it lists (a hash result beside the files of that content) count as
  one more row of their call; counts, flags, the request echo and prose do not. A typed hash with its
  algorithm in front (`sha256:<hex>`) is that hash when the name fits its length.
- A result field whose value the call was given stays in its row when the record says more than the request: a
  list of records, a size, the file a hash is of, the password an archive opened with. The recurring-indicator
  scan reads the rows a call printed, never a result set's header, and the grounding gates also read the rows
  each cited call printed past its excerpt, so no gate refuses more than before.
- The grounding gates take their markers only from the rows the cited calls printed, never from the analyst's
  own supporting_evidence, a command line or an echoed request. Every such refusal names the route: cite the
  call that prints the value, cite the call that decodes or converts it, or record the finding at SUSPECTED.
- A statement about every item that is no absence rests on a truncated cited call only when the call is about
  it: only a selective search can show it is not. An absence over a cut dump is refused with the route of a
  complete search, and a statement of the run's own means ("with the passphrases tried") is progress, not a
  claim.
- A CONFIRMED or LIKELY finding that binds files to a hash is refused when no row of its cited calls shows
  each name with the digest and no other call of the run does. A file written with its own digest in
  parentheses is one pair. The refusal says to write each file with its own digest or record the finding at
  SUSPECTED; a pair an uncited call shows is recorded as located, and the report check names a call that ran
  after the finding.
- A finding whose validated ATT&CK techniques lack a class's defining technique does not assert the class by
  weak wording: an encrypted archive is not ransomware unless the finding carries T1486.
- The adversarial evaluation reads a cited call whole when its rows fit the call's share of the evaluator's
  room. Over its share a call shows one witness per value, then the rows holding the most of the finding's
  values, and its header counts the rows not shown. A claim of exclusivity, a count or an absence over a call
  with rows not shown, or read only in part, cannot be SUPPORTED and is UNCERTAIN, naming what was not shown.
- A cited row shows more of what a finding states without binding a value to the wrong record: a minute time
  with no entity or quotation stands in a row holding one of its names, a record printed over two lines lends
  its name row the time on the line after it, a DOMAIN\user pair inside a longer path is no account, tcpdump's
  address.port shows the address, and mail dates with a month name are read as their minute. The not_shown
  line names only values no row of the trace holds.
- A finding states one fact: the record_finding description says so (several facts are several findings, sent
  in one turn), and a CONFIRMED statement of several sentences that was lowered for a value its cited rows do
  not show is told that a separate fact is a finding of its own. A sibling that repeats a recorded finding's
  template with another time, id or file is no sharper version of it.
- The refusal of a CONFIRMED finding names a SUPPORTED review of a longer or shorter form of the same words. A
  finding a content gate refused stays on the table, and the open-work list shows it until a later accepted
  finding records every name of its unobjected sentences.
- A review counts only for the exact statement it reviewed; before, a 60-character prefix matched anywhere in
  the request, so a reworded or negated statement borrowed another statement's verdict. An automatic
  evaluation is marked when it is created and runs again when the evidence holds rows it never judged.

Indicators:

- The indicator lists keep a value where a tool output that read evidence
  shows it. Each row says where it was seen (host, first and last time,
  call); a block or contain row needs a sighting its finding cites or one
  on the finding's host; a row seen only elsewhere is listed for review; a
  value only named (in a finding's wording, a recorded step, the brief or
  the threat context) and seen nowhere is listed as context ("named but
  not seen"), searched for, and never exported. A value named without a
  stated role prints as "role not stated". A typed value refused at
  record time because no call showed it is checked again each turn; once
  a call shows it, it is listed for review as "seen, refused at record
  time", never for blocking. A tool's own program, its runtime assembly
  and its symbol or cache directory no longer make a call that read
  evidence count as the run's own material. Rows recorded before this
  version stay listed as "sighting unchecked" until checked.
  ATLAS_IOC_SIGHTED_CATALOG=0 restores the earlier lists.
- An attacker address in a published content-delivery or front-end range
  (Cloudflare, Fastly, CloudFront, GitHub, Google, Microsoft 365) and a
  vendor's own service name (Microsoft, Microsoft 365, Google, Apple,
  matched by exact name) are hunt items, never block items, and carry the
  mark in every list (ATLAS_IOC_SHARED_EDGE). The lists are vendored in
  share/.common/shared_infrastructure.json and refreshed with
  devtools/build_shared_infrastructure.py at each release.
- export.export_iocs and atlas report --format stix render the indicator
  list: the same CSV as the report's indicator file and a STIX bundle of
  the located, actionable rows, each with the first time the evidence
  shows it. The text extraction from finding descriptions is gone.
- An indicator can be recorded with side `undetermined` (seen, owner not stated): it is listed with
  its sighting and no use until a later row states the side; the catalogue prints plain role labels.
  A containment step that names an address, domain, URL or mail address no tool output of this case
  shows is refused once and recorded without it when sent again. The PRIOR KNOWLEDGE block says a
  named indicator is context until the evidence shows it. Switches ATLAS_IOC_ROLES,
  ATLAS_REC_VALUE_SIGHTING, ATLAS_IOC_PRIOR_CONTEXT.
- A recorded contain, eradicate, recover or harden step that names an
  address or name on published shared infrastructure (a shared edge or a
  vendor service) is refused once naming the mark ("hunt, never block");
  recorded again as it is, the step is kept with that value moved to a
  hunt note (ATLAS_REC_MARKED_VALUES).
- Every report writer path, the projected final report included, writes the indicator files and
  records the next steps before the report is assembled, so the Indicators section never points at
  missing files; a call cited twice is one sighting of a value. Switch ATLAS_REPORT_INPUTS_AT_RENDER.
- The reminder for indicators not yet searched lists each source once, with
  one ready search pattern for every indicator still owed there, so a single
  call covers them all; a path or a registry key is searched by its last
  component, which matches any notation. A search that stopped at its hit limit counts only
  for the indicators its rows show; the others stay owed instead of being
  taken as a clean miss. Table searches also report that limit when rows had
  to be cut to fit the output.
- Once the run has been asked for its report, the reminder for indicators not
  yet searched no longer sends it back to searching, so the pre-report check
  runs; the report's Evidence Gaps list the indicators not searched in every
  relevant source.
- The check for recurring indicators before the report asks for a ruling, not a finding. A value that bears on
  the case goes in a finding; the rest go in one disposition naming each value and why it is no indicator.
  Only a value of a kind with an investigative handle (an outside address, a URL, a domain, a mail address, an
  account, a hash) blocks the report; file names and private addresses are named in a line that blocks
  nothing. The scan skips the call's command line, an OID or version string that reads as an IPv4 address, an
  a.0.0.0 network identifier, the case's own container digests and a URL cut short beside its whole. The
  Limitations list every recurring value a disposition alone ruled out, with the disposition's own clause
  about it.

Report:

- The report's Executive Summary is written in the frame the brief states (engagement type, system owner, the
  brief's question) and in none when the brief states none; how an account, a system or a person was used is said
  only where a finding states it; and its next steps are rendered by code from the recorded response plan
  ("no step recorded" when there is none) instead of being invented by the model.
- In an examination after the fact the analyst's note on recommendations says that what a finding still has to
  recover or preserve from a system is kept until that is done, and that a system the brief does not place with
  the owner (a third party's server) is altered only by a request to its operator after the preservation steps,
  so the report no longer advises removing the only copy of what it has not recovered.
- The Attack Timeline no longer shows a tool's own run time as an event: a Python tool's JSON result cited
  for a finding is read for the rows inside it and never as a record of its own, and a log line or listing row
  that names no year is dated by the year its text or the evidence file states, or left undated, never by the
  year the run happens in.
- The privileged-access step names only accounts a current finding states as administrative or
  privileged, never by the account's name; with none it waits to be scoped. Switch
  ATLAS_PRIVILEGED_OBJECTS.
- The report check no longer runs the scenario-shaped checks (account
  controller, exfiltration channels, roster, per-principal hypotheses,
  attribution closure, surfaced identities): open hypotheses and a case
  question no finding names are warnings, and a LIKELY attribution verdict
  is evaluated adversarially instead (ATLAS_REPORT_CHECK_NO_SCENARIO).
- The reviewer's blockers in reason.synthesize become proposed work items
  for the director (the synthesis result lists their ids) and a warning
  in the report check, never a blocker; no UNRESOLVABLE statement is asked
  for or read, the unread high-value artefacts are a warning naming their
  items, and open questions are a warning (ATLAS_BLOCKER_ITEMS). A refused
  malware-family name leaves a proposed look-up item.
- reason.synthesize asked again with no new finding since the last
  synthesis answers with a pointer to that synthesis and its open blocker
  items instead of a new model call, and the report check's blocker
  warning says the synthesis stands. Switch ATLAS_SYNTHESIS_STANDS.
- A run that stalls in the report phase without a synthesis gets one from
  the loop before it closes out (ATLAS_CLOSE_OUT_SPINE).
- Fix: a stopped run writes its report from the findings before it composes the answers, then replaces it
  with the composed one, so a stop that escalates to a kill still leaves a report; a second stop request ends
  the composition, and the report counts the answers that stay projections.
- The pre-report check no longer accepts a limitation that says nothing
  ("UNRESOLVABLE: none", "not unresolvable") as a reason to report with
  blocking issues open.
- A brief that names no system owner is read in a neutral frame: no side is assumed, prose values with no side
  go to review, a typed side stands on its finding's basis, an asset the brief lists takes no side, and no
  first-hour precaution or owner remediation row is seeded. The report and the analyst's prompt say "SYSTEM
  OWNER: NOT NAMED", and a handling stop hands over as in the incident frame.
- The incident window speaks in the case's frame. Outside an incident an attacker label with no stated time
  states no window, and no line says the attacker's first activity is not stated; a window with no attacker
  data gives no WINDOW block; the victim's accounts are the system owner's and the subject's the subject's in
  any frame; the answer composer writes for the examiner.

Incident map and the frontier loop:

- An incident map follows the findings (.atlas/incident_map.db): hosts, accounts, files and endpoints the
  findings name, their attacker or benign labels with the finding behind each, and timed events. It notes
  values seen on a host before the attacker's stated arrival there, proposes the hosts an attacker value
  reaches by name, hash, account or endpoint (a host with no attacker event gets a due read), and keeps the
  incident window from stated arrivals and inbound edges. Switches ATLAS_INCIDENT_MAP, ATLAS_MAP_WINDOW,
  ATLAS_MAP_SIGNALS_TO_WORK_ORDER; devtools/rebuild_incident_map.py rebuilds a finished run's map.
- A second loop, `ATLAS_LOOP=frontier` (default stays `conversation`; needs the incident map): the work
  order runs as a queue of short items, each one fresh model call with at most ten tools and a submit
  that code records through the same finding gates. Attacker values from the incident map are counted
  once per batch over the case's tables and saved outputs; the map's changes become items (host pass
  with its arrival first, folded joins, view rows, follow-ups, planned reads, evidence triage); a
  synthesis item reads the whole map once per change of its labelled state; the run ends when nothing
  is due. A resume in the other loop is refused.
- In the frontier loop an item's progress counts the records new to the run (row identities), not distinct
  sources, and an item that makes no progress for a round is told what is left. Every submit is coerced by its
  tool schema (nested fields by type only), a wrapped or double-encoded submit is unwrapped, and a submit that
  still cannot be read is answered "not read" instead of being dropped. A forced round that brings no submit
  gets one forced retry, and a forced submit's refusal gets one repair round. View-part items list the exports
  of their rows' hosts and unattributed exports, and open cells are no longer printed as filled.
- In the frontier loop a rendered row quoted by marker and time names its saved row, and the citation check
  and auto-fill find a cited value in every form JSON writes it (backslashes, quotes, \uXXXX); before, a
  Windows path in a submit was refused as uncited. A refusal carries every objection and the evaluator's
  reason, the evaluator's words travel with every verdict that is not SUPPORTED, and a failed evaluation says
  it could not run. A question id in bears_on is sent back once with the question's parts.

Reruns:

- `atlas rerun` puts findings that state an image was blocked or unread under
  review when the recount from the trace corrects that image, and the report
  lists them as under review instead of as standing gaps.
- Findings under review show "needs review" next to their confidence in the
  report.

Dashboard:

- The dashboard opens a case only by the name in its link. After *Create case* the page opens the new case;
  it used to open the case viewed before, so a *Start run* there ran that other case. A link naming a case
  the dashboard does not have now says it was not found and selects no case, and a case list that did not
  load is retried instead. A start that removes a case's working files (*Start over* on a case that ran, or
  a fresh start) asks for the case's folder name first, and the run options show which case they start.
- Case Findings has a third layout, Time: the findings grouped by day, ordered by the first moment each
  statement states (a finding that states none is counted under the list and stays in Board and List). A new
  Coverage tab shows per evidence item one bar of its content classes read, partly read, left with a reason or
  open, under it the open classes with their next step and the left ones with their reason and proof, then the
  extracted outputs' file classes the same way. It works on a case with no questions. The incident map keeps
  feeding the model and the report; it has no tab of its own.

Command line:

- The terminal banner's block wordmark reads ATLAS; the banner,
  `atlas --version`, `atlas --help` and the installer carry the tagline
  "Autonomous DFIR agent that shows its work", and the live spinner names
  plain DFIR steps.

Tools and install:

- `misc.hindsight_chrome` starts. install.sh installs `ccl_chromium_reader` and `ccl_simplesnappy` at the
  commits pinned in install-versions.env (`--no-deps`), then Brotli and zstd, and proves the install by
  importing pyhindsight's Chrome module; a failure is a warning, never an abort. The wrapper takes jsonl,
  sqlite or xlsx (default jsonl), reads the old `json` as jsonl and refuses any other value with the accepted
  set before it spawns. A run that dies on a missing Python module returns a refusal naming the module, which
  the completeness gate reads as a search that never ran, and both refusals say the browser history could not
  be parsed on this system and is a limitation.
- The Zone.Identifier reader takes values as values (a percent sign in a URL crashed it). `strings_grep`
  extracts a file once per file state. `analyzemft_parse` and `tsk_mactime` refuse an input that is not their
  kind, and so does a folder handed to a one-file reader (wrong input kind, no investigate debt). The timeline
  builder holds each event once, and the brief's main question is tracked as a task. Archive extractors say
  what the bytes hold when they refuse a file. Decode and decrypt tools write the same trace entry as any tool
  and withhold the key, IV and tag from it, and the class of what a call read follows the contents index. The
  belief-starvation latch counts one contact per model call.

Devtools:

- A run audit (`devtools/validation/run_audit.py`): for a finished run it scores traceability (which findings
  a cited call's output actually shows, minus the search's own echo) and leftover evidence (images listed but
  never read, and whether the report says so). Read-only, output to its own files; 83 tests. The run audit
  reads tool output with the same echo rule as the run itself: a field that repeats what the call asked for no
  longer counts as seen, in a single-record result too. Audit figures from earlier runs are not comparable
  with new ones on this axis.

Coverage, reasons and depth:

- Every content class inside an evidence item ends read, read in part, or left with a checked reason. A class with
  neither is open work the model sees every turn (per host, grouped by label, cheapest and highest-yield first) and
  the finish and the director's move to the report phase wait for it. A model that calls finish twice with the
  same undecided classes ends the run as unfinished ("undecided_evidence": exit code 2, "Run stopped" in the
  dashboard, a report section headed with what was stopped before it was read or ruled out, a person decides;
  a resume continues on those classes). "No reason recorded" is no longer a state a finished run can carry; an
  evidence item the class rules shape no class for counts as one cheap class of its own.
- Leaving a class takes an observation from a read on the same host ("no scheduled tasks created on this server in
  the window per the Task Scheduler log, call 12"), one call per class label across hosts, with per-host outcomes.
  The reason must name its source; an address, account, file, hash or path it names must appear in that read's
  rows, command or arguments; dates and clocks may come from the brief, the questions or the incident window; "not
  needed for the question" and the like are refused; a class holding a current attacker value cannot be left. Atlas
  records the mechanical reasons itself: empty and no parser installed only Atlas can set; unreadable (after every
  parser failed) and outside the time window Atlas also records, and the model may set them only with that proof.
- Parsers are found by the file names they declare: 36 parsers gained input-name declarations (Prefetch, registry
  and user hives, Amcache, shellbags, SRUM, jump lists, the USN journal, browser stores and more) that the class
  lookup never reached before; an undeclared format is shown as "reader: not declared" and left to the model.
- Depth of analysis per host, as cheap / medium / hard tiers counted by the calls a reading needs, is stated in
  the work block, the director's note, the pre-report check, the report ("Depth of analysis per host") and the
  Coverage tab; nothing gates on it. A host-wide question ("what happened on the hosts") stays partial until each
  host in scope has its cheap and medium classes decided, worked out live, never stored.
- A timeline row and an evidence bullet take the host from the record (its path, a host-shaped event host, the
  one host the text names), not from the finding; a digits-only host cell is dropped. A tool's own banner and
  trailer lines (identical across all of its outputs) are no longer demanded as indicators. The post-run review
  takes the case question from the run's recorded objective when -q is absent. A task-part limitation call is
  atomic, with a verdict per part and "Nothing was recorded" on refusal. Capitals in a reason count as source
  names only when they are known artefact names (every capitals word for an absence claim). The SRUM class is the
  sru folder and SRUDB.dat. Tabular tools report ragged rows (fields beyond the header's width are col<N>) with a
  note. Extracted-output classes take the extension-shape rule, so a query-string tail is no class of its own.

Command line, providers, dashboard and docs:

- The Coverage tab opens at once during a live run instead of waiting on the whole trace, and the per-turn
  open-work pass is cheaper: a tool call's read set is resolved once and kept until a listing changes or a copy
  is registered for a path it named, instead of resolving every call of the trace again after each turn.
- The per-turn coverage pass no longer re-runs the attacker-value sweep for every open class on every turn and no
  longer rebuilds the evidence profile each turn (on a case with many hosts this cost minutes per turn); verdicts
  are re-checked only when their inputs change (a new export, a new attacker value, a reopened class).
- A stop requested from the dashboard or by signal ends with one line and exit code 2 (stopped unfinished), no
  traceback; Ctrl+C is unchanged.
- The run strip and the header activity card fold a long activity text instead of running past the screen on a
  phone; the card keeps its width where there is room and narrows beside the chip on a phone.
- During the intake the status record names the step that runs ("indexing the contents of <image>, volume 1 of 2",
  "planning how to open the disk images", "recording the system baseline"), so the dashboard no longer says
  "fingerprinting" for the whole index stage.
- A start checks the analyst's provider, model and key (and the reviewer's for `train`) before it touches the
  case, so a configuration Atlas cannot use no longer costs a finished case its outputs. A start that clears moves
  the prior run's reports and trace to `.atlas/run_history/<run>/` (never deleted; a failed move puts everything
  back and refuses the clear) and removes analysis/ and exports/. `--fresh` and `--resume` are documented; exit
  code 4 means the run ended with coverage incomplete.
- `atlas rerun` refuses a context id that names no entry before it writes anything; a dry run writes nothing;
  `atlas report` renders the case's main report by the dashboard's own rule, never the newest markdown file;
  `atlas timeline --from-master` reads the Timeline Builder's file in reports/ or the newest snapshot;
  `atlas review --live` runs its free stall check first and asks the reviewer model only for a stalled run.
- A Stop from the dashboard (a SIGTERM) is recorded as a requested stop, not as a Ctrl+C, and counts as the run's
  ending; the dashboard shows "Run stopped on request", and "Run finished" only for a run that ended through a
  completion path.
- No analysis session (run, train, rerun, interactive, chat) is offered the tool that clears a case; the CLI and
  the MCP server keep it.
- Providers: a keyless local provider (Ollama, LM Studio, vLLM, llama.cpp) can start a run; a provider name that
  differs from another only in case or punctuation is refused; saving a provider makes no paid model call; an
  alias name is accepted; `~` and a relative folder work for the profile directory; an unknown preset is refused;
  the thinking level is limited to what the profile offers; a value with a space at its end (an auth prefix such
  as `Token `) is written in double quotes so the CLI, the dashboard service and docker compose read it alike;
  a key with a line break never reaches the settings file or a header; the shipped TOML profiles carry comments;
  `atlas provider profile init <id>` writes an editable copy and `atlas provider profile path` shows the folders;
  the connection test has a deadline and a Cancel; removing a provider removes all its variables.
- Dashboard: a Brief save carries the version it edited, and a save over a changed brief shows both texts instead
  of overwriting; `atlas autofill` writes only onto the brief it was made from; deleting, renaming or purging a
  case refuses a running case before any unmount; purge is admin-only with the typed case name and an activity-log
  entry; a session past its idle or absolute limit is refused on its very next request; the Coverage tab shows
  what was read, read in part, left with a reason or still open; status pills and buttons meet 4.5:1 on every
  light surface including hover.
- Docs: `atlas run`, `train`, `report`, `rerun`, `skin`, `doctor`, `guide` and `intel` are described as they
  behave (output file names, the start rule, exit codes, the tool budget, six model roles as five text roles plus
  an optional vision role, the snapshot migration, the Coverage tab, who may stop a run); `atlas skin` names the
  saved default and warns when the environment overrides it.

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
