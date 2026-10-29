# Models and providers

Atlas talks to any model that serves the OpenAI Chat Completions dialect,
which nearly every vendor it lists does, and speaks Anthropic's own Messages
API for Claude (see [Anthropic's Messages API](#anthropics-messages-api)).
The T-Systems LLM Hub is the backend to
pick when case data has to stay on EU infrastructure (GDPR/DSGVO). Nothing is
pre-selected: the wizard and the Settings page make you choose a provider
explicitly, and an unset role is off, not silently the hub. Every backend
on this page is configured the same way and equally supported.

The model roles, and where each is pointed:

| Role | Backend |
|------|---------|
| **Primary analyst** | `bin/atlas` — agentic CLI (`agent/`) driving MCP tools in-process |
| **Adversarial reviewer** (`reason.*`) | `REASON_BACKEND=<provider>` |
| **DAIR phase director** (`dair.*`) | `DAIR_BACKEND=<provider>` |
| **Run reviewer** (`atlas train` / `review`) | `ATLAS_REVIEW_PROVIDER=<provider>` |
| **Report writer** | `ATLAS_REPORT_PROVIDER=<provider>` (else the analyst's) |
| **Vision** (optional) | `VISION_BACKEND=<provider>`, model id override `VISION_MODEL` |

The wizard and Settings → Providers set the first five per provider. The
vision role is chosen on purpose and is never assigned by `--role all`:
`bin/atlas provider use NAME --role vision` (or `VISION_BACKEND`) names a
provider whose model takes images. It is used only by `images.describe`,
which describes a case picture (a carved one, for example), and only for a case whose brief states
`Vision descriptions: on` (a missing row, or any other text, is off): a
picture then leaves the workstation for that provider. The report's gap lines
name each picture class no model could identify and why (descriptions off in
the brief, no vision model, a model that takes no image). An explicit
`ATLAS_AGENT_MODEL`, `REASON_MODEL`, `DAIR_MODEL` or `ATLAS_REVIEW_MODEL`
outranks the provider's model; assigning a role on the Settings page clears
that role's override, and the Providers section warns while one is still set.

## Thinking

A thinking model pays for its thinking out of the same completion budget as
its answer. Atlas therefore sends **no completion cap** on any call unless you
set one, reads the thinking out of whichever field the provider put it in, and
never lets it become the answer. What the pipeline consumes is `content`
only; the thinking is kept for the trace.

Each provider has one setting, **Thinking**, under Settings → Providers and in the
wizard:

| Value | What is sent |
|-------|--------------|
| `auto` (default) | nothing on the first call; a level is learned if a reply comes back empty |
| `low` / `medium` / `high` | that level, spelled the way the provider takes it |

```bash
LLMHUB_THINKING=high                      # the hub provider
ATLAS_PROVIDER_<NAME>_THINKING=low        # any other provider
ATLAS_LLM_MAX_OUTPUT_TOKENS=65536         # optional: one global completion ceiling
```

**When a reply comes back empty** because the model spent its whole budget
thinking (finish reason `length`, or a reasoning count that accounts for the
completion), the request path climbs a ladder and remembers what worked, per
provider, model and role, in `~/.atlas/llm_api_compat.json`:

1. If no cap was sent and the endpoint's own default cut the reply short,
   send an explicit ceiling (65536) from now on.
2. Ask for a bounded level: `high`, then `low`, then `minimal`. `medium` is
   skipped (it is the default on most endpoints) and `none` is never sent by
   the ladder: a model that cannot stop thinking answers `none` by writing
   its thinking into the answer.
3. Compact the input (the reasoning and director roles only).

The level that answered is where that role opens from then on, so the climb
is paid once per install rather than on every call; a later starvation climbs
on from it. What the operator configured (`ATLAS_EFFORT_<ROLE>` or the
provider's Thinking setting) is never overruled by what was learned. A rung
reached through a cut the client itself made (the runaway bound below, or a
connection that ended), or one that answered only with compacted input,
proves nothing about the level and is not remembered.

A 400 that lists the values the endpoint accepts steps the level to one of
them rather than dropping the option; a 400 that names the option as
unsupported drops it for that model.

**Replies are streamed.** A chat completion is requested with `stream:
true` and folded back into one reply before anything reads it. The read
timeout then guards silence between chunks rather than the length of a reply:
a model that takes ten minutes to write a long answer is not cut off and
retried from the start, and a gateway that drops idle connections sees a live
one. A stream that ends before it finished is asked again when little had
arrived, and read as a cut reply (as at the output limit) when real output
had: a second attempt at a reply the gateway cut would be cut the same way.
A provider that answers a stream request with a plain body, or refuses
`stream` or `stream_options` with a 400, is read as before (the refused
parameter is remembered and dropped). `ATLAS_LLM_STREAM=0` switches streaming
off. `ATLAS_LLM_WIRE_DIR=<dir>` writes every request as `<time>_<pid>_<n>.request.json` with the raw stream (or plain reply) beside it, for reading a run whose replies the loop cannot use. The Responses API is not streamed.

**Thinking that does not converge is cut.** A thinking model occasionally
deliberates for ten minutes without ever beginning its answer, and a gateway
that limits a request's time then drops the whole reply. Once a role has
completed a reply in the run, a streamed reply for that role whose thinking
runs past three times the longest completed thinking, with no answer text or
call begun, is closed and read as cut; the starvation ladder then lowers the
thinking level and asks again. The scale is the model's own, per role and per
run: a verbose model sets a high bar, and nothing is bounded before a role
has answered once.

**When no function call arrives although the model tried to make one** (the
call written into the text, or an empty reply whose completion count
exceeds its reasoning count), the size of the tool list is the first
suspect: past some size a model leaves the function-calling channel, and
that size differs by model and by request. The loop cuts the loaded tool
list by a fifth, coldest namespaces first and never below the control
plane, and asks the turn again. Once a function call arrives at the cut
size, that size is remembered as `max_tools` in the same profile; a cut
that no call ever confirms is not. The next run packs its namespaces under
the remembered size and loads the rest on demand.

The remembered size is a hypothesis, not a verdict: the reply that triggered
the cut may have been noise (a first turn that narrated instead of calling),
and a ceiling learned from noise would otherwise starve every later run of
namespaces. So a run keeps testing it. When the director's work order does
not fit under the remembered size, and a function call has already arrived
in this run, the load goes one namespace past the ceiling. A function call at
that size raises `max_tools` to it; a reply that tried to call and got
nothing through unloads that namespace, returns to the ceiling it left, and
no test reaches that size again in the run. Each test costs at most one
turn, the ceiling climbs back within a run when it was set too low, and a
model that truly cannot take a larger list settles at the size it can.
`ATLAS_AGENT_MAX_OPENAI_TOOLS` stays the operator ceiling above all of this,
and `atlas provider test` shows the remembered value.

**Advanced: per-role levels.** `ATLAS_EFFORT_<ROLE>` overrides the provider
setting for one role: `AGENT` (the analyst and everything on its client),
`REPORT`, `DAIR`, `PLAN`, `HYPOTHESIZE`, `EVALUATE_FINDING`, `CITE_CHECK`,
`CONFIDENCE_SCORE`, `AUDIT_FINDINGS`, `SYNTHESIZE`. The three lookup roles
default to `low`, because thinking longer does not change what a piece of
text contains. The Settings page lists these under Providers, as the
Thinking levels group. Nothing is required: a run starts without any level set.

## Supported providers

Atlas speaks three wire dialects: Chat Completions, OpenAI's Responses API
(optional, for OpenAI) and Anthropic's Messages API (the `anthropic`
profile). A vendor without an endpoint in one of them is reached through a
gateway that has one: a [LiteLLM proxy](https://docs.litellm.ai/),
OpenRouter or the LLM Hub. What differs between vendors is a small set of
facts and request quirks, kept as data in one provider profile per vendor
(`provider_profiles/<id>.toml`, see "Provider profiles" below) and learned
from replies, never as code per vendor.

| Profile | Endpoint | Thinking control | Levels | Verified |
|---|---|---|---|---|
| `llmhub` | T-Systems LLM Hub `/v2` | `reasoning_effort` | per model; the hub lists them in its 400 | live |
| `openai` | `api.openai.com/v1` | `reasoning_effort`, `max_completion_tokens` | none…xhigh | live |
| `openrouter` | `openrouter.ai/api/v1` | `reasoning: {effort}` | none…xhigh | live |
| `anthropic` | `api.anthropic.com/v1`, Messages API, key in `x-api-key` | `output_config: {effort}`; no thinking switch is sent | low…max (minimal and none sent as low); none on Haiku 4.5 and Sonnet 4.5 | vendor docs; prompt caching on |
| `anthropic-compat` | `api.anthropic.com/v1`, Anthropic's OpenAI-compatible layer | none (the layer ignores `reasoning_effort`) | — | vendor docs; test-grade per Anthropic, no prompt caching |
| `zai` | `api.z.ai/api/paas/v4` | `thinking: {type}` + level | low, high, max; cannot switch off | vendor docs |
| `deepseek` | `api.deepseek.com` | `thinking: {type}` | default on | vendor docs |
| `gemini` | `generativelanguage.googleapis.com/v1beta/openai` | `reasoning_effort` | minimal, low, medium, high | vendor docs |
| `qwen` | DashScope compatible mode (region-specific) | `enable_thinking` | on/off | vendor docs |
| `xai` | `api.x.ai/v1` | `reasoning_effort` | low, medium, high, xhigh; cannot switch off | vendor docs |
| `meta` | `api.llama.com/compat/v1` | none | — | vendor docs |
| `mistral` | `api.mistral.ai/v1` | `reasoning_effort` | none, high | live |
| `ollama` | `localhost:11434/v1` | `reasoning_effort` | none…max; no `tool_choice` | vendor docs |
| `azure-openai` | your resource's `/openai/v1` (key in `api-key`) | `reasoning_effort` | learned | vendor docs |
| `groq` | `api.groq.com/openai/v1` | `reasoning_effort` | per model, learned | vendor docs |
| `together` | `api.together.ai/v1` | `reasoning_effort` | learned | vendor docs |
| `fireworks` | `api.fireworks.ai/inference/v1` | `reasoning_effort` | learned | vendor docs |
| `cerebras` | `api.cerebras.ai/v1` | `reasoning_effort` | per model, learned | vendor docs |
| `lmstudio` | `localhost:1234/v1` | learned | learned | vendor docs |
| `vllm` | `localhost:8000/v1` | learned | learned | vendor docs |
| `llamacpp` | `localhost:9931/v1` (llama-server's default port) | learned | learned | vendor docs |
| `local` | vLLM, LM Studio, llama.cpp, … | learned | learned | — |
| `custom` | any OpenAI-compatible gateway | learned | learned | — |

In the Verified column, "live" means the preset was checked against a running
endpoint that serves the vendor's models, and "vendor docs" that it follows the
vendor's documentation. Every reply shape Atlas reads has a fixture under
`tests/fixtures/llm/` (the Messages API's events and bodies are in
`tests/core/test_messages_api.py`), written by hand from the documented
shape, and the parser test asserts what Atlas reads from it. Where a reply is thinking:
`reasoning_content` (sglang, DeepSeek, Z.ai, xAI, vLLM with a reasoning
parser, LiteLLM), `reasoning` (vLLM, OpenRouter, Ollama), `reasoning_details`
(OpenRouter), `thinking_blocks` (LiteLLM for Claude and Gemini), `thinking`
chunks inside a content list (Mistral direct), or a leading `<think>…</think>`
block in the content (a server without a reasoning parser). All are read the
same way. DeepSeek's direct endpoint requires the thinking sent back on later
turns once tools are used; that preset does so, no other does.

## Provider profiles

Providers are data; wire formats and auth schemes are code. A profile states
what Atlas knows about one provider type: its base URL, the header the key
goes in, static headers, how a thinking level is spelled, the levels the
vendor takes, reply fields to send back, whether a temperature is refused,
whether its input rate limit counts cache reads, and how its model list
pages (`[connection] models_paging`: `after_id` reads Anthropic's list to
its end). It chooses a wire format (`dialect`: OpenAI Chat Completions,
OpenAI Responses or Anthropic Messages) and never adds one; anything else
goes through a gateway or a small code change. Rules under
`[models."<glob>"]` change `request` and `reasoning` for the model ids the
glob matches (a more specific glob after a less specific one; a rule's
`levels` change or add to the map, key by key). A configured provider (an instance in `.env`) binds
to a profile by `ATLAS_PROVIDER_<NAME>_PRESET` (the wizard and the Settings
page write it for every provider they save, except one on `custom`), else by its name in any letter
case (a provider named `OpenRouter` gets OpenRouter's request shape), else to
`custom`. Three rules keep a binding from happening by accident:

- A `_PRESET` that names no profile makes the provider unusable, with the
  reason and the known ids; it is never ignored.
- A provider is never matched to a profile by its host. One registered as
  "Other" at `api.anthropic.com` stays on `custom` (Chat Completions, no
  Anthropic headers) until `ATLAS_PROVIDER_<NAME>_PRESET=anthropic` binds it.
- A provider named like a profile that is not Chat Completions (`anthropic`)
  binds to it by name only while its base URL is that profile's own host; a
  gateway that merely carries the name stays on `custom`.

**When "Other" is enough.** The Other profile (`custom`) serves any
OpenAI-compatible gateway: a base URL, a key, a model, and, for a gateway
that wants the key in another header or after another word, the Auth header
and Auth prefix fields (Settings, or the wizard's questions for Other). A
profile file is needed for static headers, how a thinking level is spelled,
the levels a vendor takes, rules for some models, another dialect, or a
bare key in `Authorization`.

**What a profile does not decide.** Its `base_url` only prefills the form;
the URL a provider uses is the one saved with it. Its `[reasoning] levels`
decide which levels a provider can be pinned to: the wizard and Settings
offer only those (Auto always), and a save refuses another.

`[reasoning] control` says how a level goes on the wire:

| control | sent |
|---|---|
| `reasoning_effort` | `"reasoning_effort": "<value>"` |
| `reasoning_object` | `"reasoning": {"effort": "<value>"}` |
| `thinking_type` | `"thinking": {"type": "enabled"}` and `"reasoning_effort": "<value>"`; `none` sends `{"type": "disabled"}` |
| `enable_thinking` | `"enable_thinking": true`, or `false` for `none` |
| `output_config` | `"output_config": {"effort": "<value>"}` (Messages dialect) |
| `none` | nothing |

`<value>` is the level's entry in `levels` (`high = "high"` sends `high`).

- Shipped profiles: `provider_profiles/<id>.toml`, checked against
  `provider_profiles/schema.json` (editors with JSON Schema support for TOML
  can use it: each shipped file names it on its first line, `#:schema`).
  Every key in a shipped file has a comment saying what it does.
- Your own: `provider_profiles.local/<id>.toml` in the Atlas folder (ignored
  by git, like `.env`), or the folder `ATLAS_PROVIDER_PROFILES_DIR` names
  (`~` is expanded; a relative folder is taken under the Atlas folder).
  A file with a shipped id changes only what it names and keeps every later
  shipped fix; a new id adds a provider; `disabled = true` hides one. Files
  are never read from a case folder. No schema lies beside your files: point
  your editor at `provider_profiles/schema.json` in the Atlas folder.
- `bin/atlas provider profile init <id>` copies a shipped profile, with its
  comments, into your folder (its `#:schema` line pointing at the shipped
  schema); delete the lines you do not change, so later shipped fixes to
  them still reach you. `bin/atlas provider profile path` prints both
  folders.
- Three things make a first edit fail: the `id` must equal the file name
  (without `.toml`); a user file may not set `[env]` or `implicit`; and a
  file named `custom.toml` is not read (the fallback cannot be changed).

```toml
# provider_profiles.local/acme.toml: a gateway that wants its key in X-Acme-Key
schema = 1
id = "acme"
order = 5                                # position in the menu; shipped ones start at 10
label = "Acme gateway"
description = "llm.example.com, the in-house gateway."
dialect = "chat"

[connection]
base_url = "https://llm.example.com/v1"

[auth]
header = "X-Acme-Key"
prefix = ""
```

Then register it like any provider (Settings → Providers, or `bin/atlas
provider setup`) with that profile chosen. A file that fails the checks (an
unknown key, a wrong type, plain `http` to a public host, a credential
header in `[headers]`) makes the providers bound to it unusable with the
file, the key and the reason: `bin/atlas doctor`, Test connection and the
start of a run show it. Every other profile keeps working. A user file for
the fallback profile `custom` is not read at all (doctor lists it as
ignored): every provider no other profile claims binds to it. A run reads
the profiles once, at its start.

`bin/atlas doctor` shows what the binding came to: where the profiles are read
from (the shipped folder, and the ids your own folder holds), every profile
that cannot be used with its reason, and for each provider the profile it
binds to, by which rule (`preset`, `name` or `fallback`), the file or files
behind it, and where its base URL comes from (a variable, or a shipped, user
or merged profile file). A provider on `custom` at the host of a shipped
profile gets a note naming the `_PRESET` setting that would bind it.
`bin/atlas provider test NAME` prints the same binding before its calls.

## Adding a model Atlas has never seen

1. Settings → Providers → *Add provider*. Pick the vendor preset, or
   "Other (any OpenAI-compatible gateway)".
2. Base URL, API key, model id. Then **Test connection**. With a model id
   filled in it makes three short calls (under 300 tokens each): a plain
   question, one with a function tool, and, if thinking was seen, one at a
   bounded level. The report says whether the model answered, calls tools
   (the analyst role needs that), thinks and in which field, and takes a
   level. How large a tool list the model can answer is not tested here:
   that depends on the whole request, not on the list alone, so only a run can
   tell, and a run does (see "When no function call arrives" above). The test
   speaks with the chosen profile's own auth header and headers (`x-api-key`
   and `anthropic-version` for Anthropic, `api-key` for Azure OpenAI).
3. Leave Thinking on Auto and **Save provider**. A save with an API key checks
   the model list first and is refused only when the list does not vouch for
   the model (the request failed, or the list names other models and not this
   one) *and* the model does not answer either; that second check runs the
   Test connection calls (up to three short model calls). A vendor whose list
   is missing, paged or in another dialect therefore does not block a model
   that answers. *Save without testing* skips both checks. Then give each role
   the report allows this provider under *Roles in a run* and **Save roles**.
   The terminal wizard keeps its own flow.

The same check from the terminal:

```bash
bin/atlas provider setup             # the wizard, asks the same questions
bin/atlas provider test NAME         # the three calls, printed
bin/atlas provider list              # setting, whether thinking was seen, learned levels
```

A vendor with no OpenAI-compatible endpoint: run a LiteLLM proxy in front of
it (`litellm --model <vendor/model> --port 4000`, then base URL
`http://localhost:4000/v1`) or reach it through OpenRouter or the hub, and
register that as "Other".

## Setup

**Recommended: the interactive wizard.**

```bash
bin/atlas provider setup
```

Walks you through picking a provider profile from the menu (one entry per
shipped profile in the table above and per profile of your own: the Telekom
LLM Hub, OpenAI, OpenRouter, Anthropic, a local or self-hosted server, or
"Other" for any OpenAI-compatible gateway), collects the base URL/model/key,
optionally tests the connection live before saving, records the profile as
`ATLAS_PROVIDER_<NAME>_PRESET`, and points every model role (analyst,
reviewer, report, `reason.*`, `dair.*`) at it. The connection test sends the
chosen profile's own auth header. Re-run it anytime to register
another backend or reconfigure. Its logic lives in `core/llm_setup.py`,
kept free of any interactive I/O specifically so a future browser dashboard
can drive the same registration/probe/role-assignment calls from a form
instead of a terminal prompt — see that module's docstring.

`bin/atlas provider list` shows what's registered and which role uses what;
`bin/atlas provider use NAME --role ROLE --model ID` repoints an
already-registered provider without the full wizard (`ROLE` is `all`,
`analyst`, `reviewer`, `report`, `reason`, `dair` or `vision`; `all` leaves
`vision` alone). It checks the provider's model list, read to its last page,
before it writes anything.

**Recommended pairing:** the wizard marks the Telekom LLM Hub with
**z.ai GLM-5.2** as recommended (`core/llmhub.py`'s default model id), since
that is what Atlas has been developed and most tested against — it is not
pre-selected, and every other backend listed is fully supported and
equally maintained, just less
extensively benchmarked to date.

**Manual / scripted setup**, equivalent to the wizard for the hub specifically:

```bash
# 1. API key (from the LLM Hub portal) — env, .env, or GNOME Keyring:
bin/atlas-secret set LLMHUB_API_KEY

# 2. Pick a model
bin/atlas models                 # lists ids available to your key
export LLMHUB_MODEL=GLM-5.2

# 3. Point the reasoning surfaces at the hub (the wizard does this; an unset role is off)
export REASON_BACKEND=llmhub
export DAIR_BACKEND=llmhub

# 4. Sanity-check the resolved configuration
bin/atlas doctor
```

`TSYSTEMS_API_KEY` is accepted as an alias for `LLMHUB_API_KEY`. Role-specific
vars (`REASON_URL`/`REASON_MODEL`, `DAIR_URL`/`DAIR_MODEL`,
`ATLAS_AGENT_MODEL`) override the shared `LLMHUB_*` values, so each role can
use a different model on the same hub. For any other backend (OpenAI, local,
a second gateway), see `core/providers.py`'s module docstring for the full
`ATLAS_PROVIDERS`/`ATLAS_PROVIDER_<NAME>_*` var reference — or just use the
wizard, which writes exactly these vars for you.

## Anthropic's Messages API

The `anthropic` profile speaks Anthropic's own API (`POST /v1/messages`,
streamed). Atlas builds each request in the Chat Completions shape every role
uses and translates it just before it goes on the wire; the reply comes back
through the same transport (retries, deadlines, stream guards, the 400
adaptation, the token ledger). What the translation does:

- **Prompt caching.** Three 5-minute cache entries: the system prompt (with
  the tool list, which comes before it), the case brief, and the history up to
  the block before the trailing user text (the per-turn steering stays outside
  the cached part). Only the leading system message becomes the top-level
  `system`; a later one is sent as user text, so the cached part never moves.
  The usage page counts cache writes and reads into a call's input; the cached
  share is what was read.
- **Thinking.** A level goes out as `output_config.effort` (`low`, `medium`,
  `high`, `xhigh`, `max`); `minimal` and `none` are sent as `low`, and no
  `thinking` field is sent, so current models think adaptively. Claude Haiku
  4.5 and Sonnet 4.5 get no level (they take thinking only as a token budget,
  which Atlas does not send); Opus 4.6 to 4.8 and Sonnet 4.6 think only when a
  request asks, which this profile does not. Thinking is not sent back on
  later turns: Atlas edits its history in place (nudge stubs, compaction), and
  replayed thinking after such an edit is refused on accounts the
  history-editing check covers.
- **Always a completion cap** (`max_tokens`, 65536 unless set): the API
  requires one. A model with a lower maximum (64000 on the 4.5 models) is told
  apart by its first 400, which names the maximum: Atlas sends that and
  remembers it, as it does for any provider whose 400 names one. No
  `temperature` (current models refuse a non-default one) and no
  `response_format`.
- **Forced tool use** (`tool_choice` required) is sent as `auto` on the models
  that refuse it (Sonnet 5.5, Opus 5.5, Fable 5.1, Mythos 5.1).
- **Refusals.** When Anthropic's safety classifiers decline a request
  (`stop_reason: refusal`), the turn ends there without a retry: the run's
  trace shows the category and explanation, the token ledger records the call
  as `refused`, and any partial output is dropped. The next request carries
  one line, "The provider declined the last request (category: ...).
  Continue the analysis with a different approach or other evidence.";
  three declines in a row end the run with stop reason `model_refusal`. The
  chat shows the decline instead of an answer and does not ask again. A
  Chat Completions `content_filter` finish is treated the same.

The OpenAI-compatible layer stays available as `anthropic-compat`
(`ATLAS_PROVIDER_<NAME>_PRESET=anthropic-compat`). Anthropic calls it
test-grade; it supports no prompt caching and ignores the thinking level, so
no thinking budget is sent (current Claude models refuse one). It sends the
`anthropic-version` header on every request, its chat calls included, since
Anthropic's model list refuses a request without it. A
provider saved with `_PRESET=anthropic` uses the Messages API from its next
call on; shapes Atlas learned for it on the compatible layer are not reused.

## API dialect (hub vs OpenAI)

Atlas’s default chat dialect is the **Telekom / T-Systems LLM Hub** style:
classic OpenAI-compatible `max_tokens` + `temperature` (GLM, Llama, …).

If you temporarily point `bin/atlas` at another OpenAI-compatible endpoint
(e.g. `api.openai.com`), the client **learns**
per-`provider|model` quirks from HTTP 400s and stores them in
`~/.atlas/llm_api_compat.json`. Switching back to `LLMHUB_*` does not reuse
OpenAI-learned profiles — the cache key includes the provider name.

Newer OpenAI GPT-5 models still use this Completions path and Atlas's own
tools. GPT-5.4+ rejects Completions requests that combine function tools
with the model's default reasoning, so Atlas sends `reasoning_effort=none`
on those tool turns (first-guess for GPT-5 / o-series ids, otherwise
learned from the 400). Atlas does not use OpenAI hosted tools
(web search, code interpreter, …). Responses is optional and not required
for that.

Optional env:

| Var | Effect |
|-----|--------|
| `ATLAS_LLM_COMPAT_SOFT_HINTS=0` | Disable first-guess GPT-5-style hints |
| `ATLAS_LLM_COMPAT_CACHE` | Override cache path |
| `ATLAS_LLM_MAX_COMPLETION_TOKENS=1\|0` | Force limit field globally |
| `ATLAS_LLM_ALLOW_TEMPERATURE=1\|0` | Always send a temperature, or never |

## Running an investigation

```bash
bin/atlas run --case ~/Atlas/demo-cases/nitroba \
    --question "Who was responsible for the harassing posts?"
```

The agent starts the execution log, verifies evidence hashes, raises
competing hypotheses, and drives the DAIR loop to a gated final report.
Progress is narrated per turn; a JSONL transcript is written to the case's
`analysis/` directory alongside the normal execution trace.

Interactive mode:

```bash
bin/atlas chat --case ~/Atlas/demo-cases/nitroba
```

Other commands: `atlas models`, `atlas doctor`, `atlas serve` (plain MCP
stdio server, for connecting any other MCP client). The full command guide —
which command when, worked examples, exit codes, and remote SIFT execution
— lives in [cli.md](cli.md).

## Tool namespaces are lazy-loaded

The MCP server exposes hundreds of tools; shipping every schema each turn would waste
most of the model's context. The agent exposes a core set (`misc`, `reason`,
`dair`, `hash`, `ewf`, `coverage`) plus meta-tools:

- `atlas_list_namespaces` — inventory of every namespace and tool
- `atlas_load_namespaces` — load what the current phase needs

Calling a tool in an unloaded namespace loads it automatically. The tool
list spells every name as the playbook's dotted name with an underscore
(`vol.pslist` is listed as `vol_pslist`), because that is what a model
writes after reading the playbook, and an endpoint drops a function call
whose name is not in the list. The dotted form and the MCP name with its
doubled namespace (`vol_vol_pslist`) are still accepted on execution.
`--all-tools` loads tool namespaces up front until the schema budget is full
(it follows the model's context window; `ATLAS_AGENT_MAX_OPENAI_TOOLS` or the
provider profile's `max_tools` can change it); the rest still load on demand.

**A stable list where the window allows it.** A provider caches the tool list
ahead of everything else, so a list that changes forces the cached prompt to
be sent (and on Anthropic written to the cache at the cache-write price) again.
A provider profile says how many tools one request may carry (`[request]
max_tools`, set for Anthropic) and the model's window bounds it at one schema
per 2,000 tokens. An analysis run on a model whose window holds every schema
lists every Atlas tool from its first turn, and the list never changes; the
run's stderr says `atlas: tool list: stable, N schemas`, or why the namespace
mode applies instead. A 200K-window model keeps 128 tools and the namespace
switching, and so does a chat. In the namespace mode the schema array still
changes only when the model loads a namespace: namespaces are listed in the
order they were loaded and a preload only fills free room
(`ATLAS_TOOL_ARRAY_STABLE`, on by default).

## Rate limits

Providers enforce per-model input/output tokens-per-minute and requests-per-
minute caps. Long investigations resend
a large context each turn, so the input cap is the one you hit. The agent
handles this two ways:

- **Proactive pacing** — the client tracks its own trailing-minute input-token
  spend and sleeps before a request that would exceed
  `ATLAS_AGENT_INPUT_TPM` (default 400000; `0` disables). Set it a little
  under your key's input quota. It counts what the provider's limit counts:
  every input token, unless the provider profile says its limit leaves cache
  reads out (`[request] rate_limit_counts_cache_reads = false`, set for
  Anthropic, whose input limit counts uncached input and cache writes only).
- **Patient 429 handling** — a rate-limited response is retried after the wait
  the provider itself suggests (`Retry-After` header or the "try again in N
  seconds" hint in the body), without consuming regular retry attempts, up to
  a total of `ATLAS_AGENT_RATE_LIMIT_WAIT` seconds (default 600).

A provider that answers "rate limited" without saying how long to wait is
asked again after 2, 4, 8, 16 and then 30 seconds; a stated wait still wins.
An HTTP 529 (overloaded; Anthropic's `overloaded_error`) is retried with the
backoff a 503 gets.

If you still hit the cap constantly, lower `ATLAS_AGENT_CONTEXT_CHARS`
(derived from the probed window; ~3 000 000 chars for a 1M-token model)
so each turn sends less context.

## When a model call is lost

A reply the provider or the connection cut is a failed reply, never the
model's words. Once the analyst has answered in a run, a lost call does not
end or wrap up the run: the turn is asked again after a pause (60 seconds,
doubling to 5 minutes), and what it asks changes with each loss. First the
same request once after a quick loss, then one thinking level lower, then a
short progress question without tools, then the same question over a
shortened history. The summary the model gives is followed by one request with
the tools back that asks for the next step as one call. The run carries on by
itself when the provider answers again. A provider error event inside a stream
counts as a failure, not as the model's reply. A run whose provider never
answered at all stops with the error after two paused re-asks, since that is a
configuration problem.

The run log shows every loss and every recovery, also in quiet mode, and the
dashboard's Overview names what the run does next; after
`ATLAS_ESCAPE_ALERT_SECONDS` (default 30 minutes) of failing calls it shows an
alert. The alert is attention, not a limit: the run keeps waiting.
`ATLAS_MODEL_CALL_ESCAPE=0` restores the earlier retries and wrap-up.

**When a provider declines on safety grounds** (Anthropic's `refusal` stop
reason, a `content_filter` finish elsewhere) the turn ends without a retry, as
described under [Anthropic's Messages API](#anthropics-messages-api).

**Single-answer calls are bounded in what they may write.** The answer
composer, the question planner, the director, the reason tools, the reviewers
and the report sections each want one reply. Each is asked under an output
allowance of 64,000 tokens (`ATLAS_ONE_ANSWER_MAX_TOKENS`; the switch is
`ATLAS_ONE_ANSWER_ALLOWANCE`). A reply that runs past it is asked again once at
a lower thinking level and then falls back, so one runaway reply cannot burn a
whole completion window. A helper whose reply was cut is not sent the same
request again in the same run until a later call of that tool answers, and a
helper that gives no usable answer to three requests in a row becomes a
documented limitation in the report, not a blocker.

## Model context auto-probe (LLM check)

At the start of every `atlas run` / `train` / `chat` session Atlas issues a short
`GET /models` against the configured provider (with the provider's own
headers, so Anthropic's model list answers), finds the active model id, and
reads a context-window field from the live JSON (`context_length`,
`max_model_len`, `max_input_tokens`, nested `top_provider.context_length`,
…). A field that states the window is read before `max_tokens`, which next to
one is the output cap (Anthropic lists both), so each model gets its full
window. A model list that comes in pages is read to its end wherever Atlas
reads it (this probe, `atlas models`, `atlas doctor --probe`,
`atlas provider use`, Test connection), so a model past the first page is
found, and a model set by an alias (`claude-haiku-4-5`) matches the newest
dated snapshot the list holds for it. There is **no** local model catalogue. The recommended / default window is **1 000 000 tokens**
(GLM-5.2). Below **32 000 tokens** Atlas switches to compact / disk-first
mode (parse on disk, summaries in chat).

- Window feeds `core.llm_check` session limits and `core.context_budget`
  (detail policy / input-scale).
- `ATLAS_AGENT_CONTEXT_CHARS`, per-tool output caps, and the max number of
  concurrent tool schemas are **derived from that window** — they grow for
  large models and shrink for small ones so Atlas never *plans* to send more
  than the window holds. Disable the char move with `ATLAS_CONTEXT_CHARS_LOCK=1`
  or `ATLAS_CONTEXT_AUTO_CHARS=0` (tool caps still follow the window).
- Before each LLM request Atlas estimates tokens of system + conversation +
  tool schemas. If that exceeds 75% of the window it compresses from the
  inside out: the **system prompt is never dropped**; older user/assistant
  turns are shortened first; full tool replies become stubs (the execution
  trace keeps the originals). That is what prevents provider-side head
  truncation (forgotten playbook gates) and HTTP overflows.
- `ATLAS_MODEL_CONTEXT_TOKENS` remains a hard operator override.
- `ATLAS_MODEL_CONTEXT_PROBE=0` disables the network call; a short disk cache
  under `~/.atlas/model_context_cache.json` is used only if the live probe fails.
  With no probe and no cached window Atlas installs a conservative 128 000
  token window — set `ATLAS_MODEL_CONTEXT_TOKENS` to the model's real size.
- `atlas doctor --probe` prints the discovered context for the configured model
  when the provider exposes it.

## Known limits

- **Firewall false positives.** A provider may sit behind a web application
  firewall. Forensic content is attack-shaped by nature, and an occasional
  request is rejected (HTTP 418, or 403 with a firewall notice) — after which
  the source may be briefly blocked. The agent handles this by dropping the
  offending tool output from context, waiting out the cooldown, and steering
  the model toward narrower queries; the full output always remains in the
  execution trace. If it happens often, ask the provider to relax its
  firewall rules for your key.
- **Model quality matters.** The playbook's gates (hypothesis discipline,
  citation checks, pre-report blocks) are enforced server-side, so a weaker
  model fails loudly rather than hallucinating quietly — but expect more
  correction loops with small models. `GLM-5.2` (default) and the
  larger hub models handle the flow well.
- **Thinking takes time.** With Thinking on Auto a long-thinking model may
  spend a minute or two on a synthesis or a director call. `low` answers in
  seconds with output that still parses; the per-role overrides are where
  that trade is made.
- **Chat Completions is the default LLM dialect.** Atlas's agent loop still
  thinks in Completions `messages` / `tool_calls`. New OpenAI models keep
  that loop; Atlas does not need OpenAI hosted tools. OpenAI's **Responses
  API** (`POST /v1/responses`) remains an optional per-provider transport
  (`ATLAS_PROVIDER_<NAME>_API=responses`). Atlas never infers it from a
  model id and never assumes an OpenAI-compatible URL speaks Responses.
  Unset / unknown stays on Completions so existing `.env` files keep working.
  Anthropic's Messages API is the `anthropic` profile's own dialect, chosen by
  the profile and never by a model id.
