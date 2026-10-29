# The dashboard

`./dashboard.sh` serves it on `http://127.0.0.1:8765`; `install.sh
--with-dashboard-service --with-dashboard-lan` runs it on boot and on the
LAN over HTTPS (org certificates go in `/etc/atlas/dashboard/tls.crt` +
`tls.key`). The first visit creates the admin account. Pages update
themselves while a run writes — a change feed announces every write under
the cases root — so nothing needs a reload, and a hidden tab does no work.

## Case tabs

| Tab | What it shows |
|---|---|
| **Overview** | One status band: the run's state and its Start/Stop controls, the questions answered, findings by confidence, indicators, the response plan, open conflicts, evidence files — and what the run is doing right now (during the intake, the step that runs: "indexing the contents of <image>, volume 2 of 10", "planning how to open the disk images", "recording the system baseline"). Below it: recent findings, the response plan's top items, the indicators, the live activity. While model calls are being lost the activity line says what the run does next, and after half an hour of failing calls it carries an alert ([When a model call is lost](llm.md#when-a-model-call-is-lost)). |
| **Questions** | Every investigation request with its status and the conclusion that answers it. A question over several hosts with no single artefact, value or host of its own ("what happened on the hosts") stays partial until each host in its scope has its cheap and medium content classes decided; its answer carries that depth. |
| **Case Findings** | Every recorded belief — observations, claims, hypotheses, conflicts, conclusions and recommendations — in three layouts, each card with its evidence trail: **Board** (cards by confidence and host), **List** (one sortable list) and **Time** (the findings grouped by day, ordered by the first moment each statement states; a finding that states no moment is counted under the heading and stays in Board and List). The layout is remembered in the browser. |
| **Coverage** | What the run did with each piece of evidence. Per evidence item, grouped by host, one bar of its content classes: read, partly read, parsed (output exists, no row looked at), left with a reason, or still open. Each host's line counts the undecided classes first (no read and no reason: the ones a person or the run must still act on), then read, partly read and left. A second line gives the depth per host: for each cost tier, cheap, medium and hard, the classes decided out of those the host holds. A tier comes from the calls and time a reading needs, never from a list of artefacts, and nothing gates the run on it, except that a host-wide question stays partial (see Questions). A reason names its kind: unlikely to help (an observation from a read on the same host, with that call), outside the incident window, outside the scope, a duplicate of other evidence, unreadable, or no reader parses it; Atlas sets four itself: every file empty and no reader declaring its format, which only Atlas can set, and unreadable after its readers failed and outside the window, which the model may also state with their proof; the other kinds are the model's, each checked against its proof. Under it the open classes with their next step, the left ones with their reason and the calls that prove it, and the read ones folded away; below the items, the same for the files the tools extracted. It works on a case with no questions and updates while the run writes. |
| **IoCs** | Indicators the findings record as attacker activity (typed on a finding, never harvested from raw tool output), as cards by confidence and type or host, or as one sortable list, each with the beliefs behind it. A value is kept where a tool output that read evidence shows it, and the row says where it was seen: host, first and last time and the calls. A value only named (in a finding's wording, the brief or the threat context) and seen nowhere is listed as context ("named but not seen"), searched for and never exported. An attacker address inside a published content-delivery range, or a vendor's own service name, is marked as a hunt item and never offered as a block. The detail sheet also shows where the value was searched, where a search is still owed, and the rows counted for it in every table of the case. Copy one, or everything the filters leave. |
| **Response** | What to do about it: every recommendation with its phase (contain, eradicate, recover, harden, escalate), scope (host, network, estate), urgency and the findings it rests on, *Do now* first. Analysts and admins mark items done or not applicable; viewers read. Copy as a checklist. |
| **Process** | The run's figures, a chart of the run in time, and every step of the run in a filterable list. The chart drives the list: a phase, a lane, a batch of calls or a single mark scopes or jumps it, a drag across it picks a window. The wheel zooms the chart's time axis about the pointer and shift+wheel slides it; its header folds the chart away when the list needs the room. |
| **Report** | The current report, with the table of contents and finding anchors. A format picker beside it downloads the same report as Markdown, HTML or PDF; the latter two are rendered when the link is followed, so a download always matches the file on disk. |
| **Brief** | The case file (`CASE.md`) — investigation requests, and *What you already know*. This is the one place questions and facts live: the start dialog's quick-add and the CLI's `atlas rerun -q` write into it too, and a run picks up whatever is there. *AI Autofill* proposes Evidence Links rows for files not yet listed and shapes *What you already know* into one bullet per fact (Windows accounts as `DOMAIN\user`, a request written there moved to Investigation Requests), for review before Save. A save is refused when the brief changed after the tab loaded it (another user's save, a quick-add, a rerun's fact): the editor then shows the saved version, with your unsaved text beside it to copy from or to put back with *Use mine instead*. A tab with no unsaved edits reloads by itself when the brief changes. `atlas autofill` likewise writes nothing when the brief changed while it waited for the model. |
| **Timeline** | The curated master timeline; shown only while the timeline addon is on. |

**Which case a page shows.** A page opens the case named in its link
(`?case=<case folder name>`). *Create case* opens the case it just made. A link that
names a case the dashboard does not hold says so ("Case ... was not found. Pick a
case from the list."), selects no case and leaves the case chosen before untouched;
it never falls back to another one, because a *Start run* on a case nobody asked for
would act on that case's files. A case list that did not load is retried, and the
case is not called unknown meanwhile. With no case in the link the page opens the
case chosen last, or the only case there is.

Two pages sit outside the case tabs:

- **Brain** (analysts and admins) shows what Atlas learned across
  investigations: *Inbox* holds the candidate lessons to approve or reject
  (approving needs the operator secret), *Knowledge* the notes runs already
  use, and *Case impact* what the background learning took from the selected
  case (lessons considered, staged and filtered out). A link on the page opens
  *Brain Earth*, a page of its own that draws them as a 3D graph. See
  [second-brain.md](second-brain.md).
- **Ask Atlas**, the chat button on every page, talks about the selected case
  and runs forensic tools when it needs to. A viewer's chat cannot change the
  case, and viewers chat only when the admin allows it.

Recommendations arrive from three sources and each says which: recorded by
the investigation as findings land, derived from MITRE ATT&CK's mitigations
for the techniques a substantiated finding names, or seeded from *What you
already know* as first-hour precautions (isolate without powering off,
preserve volatile state, do not pay before legal is involved, and so on) —
those carry no evidence basis and are labelled *prior knowledge*.

## Starting a run

*New case* asks for the case id, the investigation requests and the report
language (English is recommended: the models are trained mostly on it and
tend to give sharper findings and recommendations). *Start run* on the
Overview runs a case for the first time; once a case has run, the button
reads *Continue* and picks up what changed since the last run: evidence
added under `evidence/`, questions and facts added to the brief, findings
marked for review. It keeps everything else and starts the investigator only
when there is something to do. *Options* opens the same start with a mode
picker, *Continue* or *Start over* (a full run: the previous run's report
and trace are moved to `.atlas/run_history/`, `analysis/` and `exports/` are
deleted, the findings and questions kept, all evidence examined again), and
two quick-add fields, *New questions for Atlas* and
*New context (what you now know)*, one per line, written into the brief
before the run starts. The dialog is headed with the case's folder name, so it
says which case it starts. A start that removes the case's working files
(*Start over* on a case that has run, or a fresh start) first asks you to type
that folder name, and the server refuses such a start without it (HTTP 400),
so a stale page or a script cannot wipe another case; *Continue*, a resume and
the first run of a new case never ask. A run the dashboard tracks
stays stoppable even if its folder is gone. New evidence goes into the case's `evidence/` folder
(or the network share); the run finds it by fingerprint. Under the run
controls the Overview shows what the last pre-run pass found: the evidence
delta, findings to re-validate, open questions, facts added or withdrawn, or
that nothing changed since the previous run. A case that states no question
is investigated under *What happened on the Host(s)?*. Whoever pressed Start
is mailed when the run ends, with the outcome and counts and no case
content, once a mail server is configured.

**What the run strip says.** The strip across the top of the Overview's
status band shows the run's state, phase, turn, elapsed time, tokens and
current activity beside the run controls; a long activity text wraps on a
phone. A live run reads *Run in progress*, or *Run in progress (started via
CLI)* when the dashboard did not start it (such a run is started and stopped
from the terminal). After a Stop it reads *Stopping: the run writes its
report* until the report is written. An ended run reads *Run finished* when
it reached one of its endings, *Run finished, coverage incomplete* for exit
code 4, and *Run stopped by* the user who pressed Stop. Otherwise it says why
the run stopped, for example *Run stopped — content classes have neither a
read nor a reason*: the classes are counted per host and the Coverage tab lists them, and a
resume continues on them (`atlas run --resume`, or the start mode *resume*
under *Options*). The activity panel keeps
the reason of the last ending after a dashboard restart (*Run stopped on
request* after a Stop), and a requested stop is not shown as an error.

## Settings (admin)

One page with a sidebar of sections in four groups, and an Overview first. The
section is part of the address (`config.html#usage`), so a reload or a shared
link opens the same one. `/` or Ctrl+K reaches the search above the sidebar,
which finds a section by its name or by a setting in it. Each group of settings
saves on its own and says when something in it is unsaved; a destructive action
asks for confirmation beside its button.

| Section | What it does |
|---|---|
| **Overview** | What needs attention on this host, such as the analyst role without a provider, a role served by a provider with no API key, missing programs, mail that is not set up or a model without a price, and tiles that summarise the main sections and open them. |
| **Providers** (AI models) | Providers (preset, which is the provider profile and also names the wire format; base URL, model, API key and where it is kept, Thinking setting; *Test connection* and *Save provider* speak with the preset's own headers, see [docs/llm.md](llm.md#provider-profiles)). **Roles in a run** gives each of the five text roles (analyst, reasoner, phase director, reviewer, report writer) plus an optional vision role (its model must take images) its provider; nothing is pre-selected. A warning names any `*_MODEL` override in `.env` that would outrank the provider's model; saving a role's provider clears that role's override. **Thinking levels** set how hard each role is asked to think before it answers, with what each role does and what it costs to move it. A level left unset follows the provider's own Thinking setting, except the three lookup roles, which default to low; none is required to start a run. See [docs/llm.md](llm.md#thinking). |
| **Token spend** (AI models) | Every model request made for a case, grouped by month or ISO week (UTC) and by run, with the tokens and cost of each run, case and period. Tokens written to a provider's prompt cache are counted apart from input, and requests lost to a cut stream have their own column (no tokens, no cost). A rerun's calls are counted once. The runs are paged, 25 per page by default, with 10, 25, 50 or 100 to choose. *Export CSV* downloads the rows (the last column is `cache_write_tokens`); entries can be deleted all at once or before a date. |
| **Prices** (AI models) | A price per million tokens per provider and model (input, cache read, cache write, output) and the currency label the spend is shown in (USD unless changed; a label, nothing is converted). Cache reads and writes left empty are billed at the input price. A model priced higher for long prompts takes a second set of prices under *Long prompts*, with the prompt length they start above; each request over it is priced at them, its cached tokens counted towards the length. A model without a price is counted, not costed. With **Autoremove** on, a model removed under Providers leaves the price list too. |
| **Users** (People) | Accounts and roles (viewer, analyst, admin); password resets. |
| **Sign-in and sessions** (People) | **Session limits**: an idle timeout, slid forward by every request, and an absolute limit counted from sign-in, both effective on the next request. Also whether viewers may use chat. |
| **Activity log** (People) | Who signed in or out, who started or stopped a run, who changed an account and who renamed, deleted or purged a case (`case_move`, `case_delete`, `case_purge`), with a filter, pages, *Export CSV* and how long entries are kept. |
| **Cases** (Investigation) | Cases on this host: rename, delete. A deleted case moves into `.deleted/<case>-<UTC time>/` under the cases root, evidence and all, where it can be recovered by moving the folder back by hand (there is no restore button). Deleting and renaming end an open *Ask Atlas* chat for the case and unmount its evidence first; they are refused while a mount stays, while a run is in progress (one the dashboard started a moment ago included), or when the case folder sits on another filesystem than the cases root. The admin API also takes `"purge": true` on `case/delete`, which removes the case and its evidence for good to free the disk; it needs `"confirm_case"` set to the case name, is recorded in the activity log, and, if the removal fails half way, names the `.deleted/<case>-<time>-purging` folder left to delete by hand. |
| **Enrichment keys** (Investigation) | VirusTotal, AbuseIPDB, OTX, urlscan, MISP. All optional; a saved key takes effect immediately. |
| **MITRE ATT&CK** (Investigation) | Which release this machine's ATT&CK tables are on, and a button that refreshes them from MITRE's current release, with a status tracker. |
| **Tool health** (System) | Every program a tool can call and whether this machine has it, what should have installed it, and which are optional or retired. |
| **Plugins** (System) | Addons on and off; upload a new one. Off means off: tools and events alike. |
| **Network share** (System) | An SMB share to copy evidence in from Windows without SSH. |
| **Mail** (System) | The SMTP relay Atlas sends through (host, port, user, password, from, STARTTLS), with a connection test before saving. Used for password resets and run-finished notices. |

## Roles

| Role | May |
|---|---|
| viewer | Read every case tab and the report; chat only if the admin allows it |
| analyst | Everything a viewer may, plus create and run cases, stop the runs they started, mark recommendations done, edit the brief, contribute to the brain |
| admin | Everything, plus Settings and stopping any run |

Every route is gated on the server; the page only hides what a role may not
do. A run is stopped only by the user who started it or by an administrator
(`case/run/stop` answers 403 to anyone else); a run that recorded no starter
(started before runs carried one) may be stopped by any analyst.

## Running behind a reverse proxy

Proxy to the loopback port, pass the `Host` header through, add the proxy's
DNS name to `ATLAS_DASHBOARD_EXTRA_HOSTS`, and do not buffer
`/_dashboard/api/events` — it is a server-sent event stream (nginx:
`proxy_buffering off`). A cases root on a network share needs
`WATCHFILES_FORCE_POLLING=1` so the change feed polls instead of waiting for
inotify.

## Related

`docs/llm.md` (backends), `docs/network-share.md`, `docs/addons.md`
(writing addons), `docs/investigation-state.md` (what the tabs read).
