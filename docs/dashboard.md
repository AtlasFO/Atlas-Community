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
| **Overview** | One status band: the run's state and its Start/Stop controls, the questions answered, findings by confidence, indicators, the response plan, open conflicts, evidence files — and what the run is doing right now. Below it: recent findings, the response plan's top items, the indicators, the live activity. |
| **Questions** | Every investigation request with its status and the conclusion that answers it. |
| **Case Findings** | Every recorded belief — observations, claims, hypotheses, conflicts, conclusions and recommendations — as cards by confidence and host, or as one sortable list, each with its evidence trail. |
| **IoCs** | Indicators attributed to attacker activity — derived from recorded findings, never from raw tool output — as cards by confidence and type or host, or as one sortable list, each with the beliefs behind it, where it was found and where it is still owed a search. Copy one, or everything the filters leave. |
| **Response** | What to do about it: every recommendation with its phase (contain, eradicate, recover, harden, escalate), scope (host, network, estate), urgency and the findings it rests on, *Do now* first. Analysts and admins mark items done or not applicable; viewers read. Copy as a checklist. |
| **Process** | The run's figures, a chart of the run in time, and every step of the run in a filterable list. The chart drives the list: a phase, a lane, a batch of calls or a single mark scopes or jumps it, a drag across it picks a window. The wheel zooms the chart's time axis about the pointer and shift+wheel slides it; its header folds the chart away when the list needs the room. |
| **Report** | The current report, with the table of contents and finding anchors. A format picker beside it downloads the same report as Markdown, HTML or PDF; the latter two are rendered when the link is followed, so a download always matches the file on disk. |
| **Brief** | The case file (`CASE.md`) — investigation requests, and *What you already know*. This is the one place questions and facts live: the start dialog's quick-add and the CLI's `atlas rerun -q` write into it too, and a run picks up whatever is there. *AI Autofill* proposes Evidence Links rows for files not yet listed and shapes *What you already know* into one bullet per fact (Windows accounts as `DOMAIN\user`, a request written there moved to Investigation Requests), for review before Save. |
| **Timeline** | The curated master timeline; shown only while the timeline addon is on. |

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
picker, *Continue* or *Start over* (a full run: the previous run's working
files and report are wiped, the findings and questions kept, all evidence
examined again), and two quick-add fields, *New questions for Atlas* and
*New context (what you now know)*, one per line, written into the brief
before the run starts. New evidence goes into the case's `evidence/` folder
(or the network share); the run finds it by fingerprint. Under the run
controls the Overview shows what the last pre-run pass found: the evidence
delta, findings to re-validate, open questions, facts added or withdrawn, or
that nothing changed since the previous run. A case that states no question
is investigated under *What happened on the Host(s)?*. Whoever pressed Start
is mailed when the run ends, with the outcome and counts and no case
content, once a mail server is configured.

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
| **Providers** (AI models) | Providers (any OpenAI-compatible endpoint: preset, base URL, model, API key and where it is kept, Thinking setting). **Roles in a run** gives each of the five roles (analyst, reasoner, phase director, reviewer, report writer) its provider; nothing is pre-selected. A warning names any `*_MODEL` override in `.env` that would outrank the provider's model; saving a role's provider clears that role's override. **Thinking levels** set how hard each role is asked to think before it answers, with what each role does and what it costs to move it. A level left unset follows the provider's own Thinking setting, except the three lookup roles, which default to low; none is required to start a run. See [docs/llm.md](llm.md#thinking). |
| **Token spend** (AI models) | Every model request made for a case, grouped by month or ISO week (UTC) and by run, with the tokens and cost of each run, case and period. The runs are paged, 25 per page by default, with 10, 25, 50 or 100 to choose. *Export CSV* downloads the rows; entries can be deleted all at once or before a date. |
| **Prices** (AI models) | A price per million tokens per provider and model (input, cached input, output) and the currency the spend is shown in. A model without a price is counted, not costed. With **Autoremove** on, a model removed under Providers leaves the price list too. |
| **Users** (People) | Accounts and roles (viewer, analyst, admin); password resets. |
| **Sign-in and sessions** (People) | **Session limits**: an idle timeout, slid forward by every request, and an absolute limit counted from sign-in, both effective on the next request. Also whether viewers may use chat. |
| **Activity log** (People) | Who signed in or out, who started or stopped a run and who changed an account, with a filter, pages, *Export CSV* and how long entries are kept. |
| **Cases** (Investigation) | Cases on this host: rename, delete. A deleted case moves into `.deleted/`, where it can be recovered; deleting unmounts the case's evidence first, and is refused if a mount stays or a run is in progress. |
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
| analyst | Everything a viewer may, plus create and run cases, mark recommendations done, edit the brief, contribute to the brain |
| admin | Everything, plus Settings |

Every route is gated on the server; the page only hides what a role may not
do.

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
