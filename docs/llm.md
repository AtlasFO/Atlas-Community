# Models and providers

Atlas talks to any model that serves the OpenAI Chat Completions dialect,
which every vendor it lists does. The T-Systems LLM Hub is the backend to
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

The wizard and Settings → Providers set these per provider. An explicit
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

Atlas speaks one wire dialect, Chat Completions (plus the optional Responses
API for OpenAI). A vendor without an OpenAI-compatible endpoint is reached
through a gateway that has one: a [LiteLLM proxy](https://docs.litellm.ai/),
OpenRouter or the LLM Hub. What differs between vendors is a small set of
request and reply quirks, kept as data in the preset table
(`core/llm_setup.py`) and learned from replies, never as code per vendor.

| Preset | Endpoint | Thinking control | Levels | Verified |
|---|---|---|---|---|
| `llmhub` | T-Systems LLM Hub `/v2` | `reasoning_effort` | per model; the hub lists them in its 400 | live |
| `openai` | `api.openai.com/v1` | `reasoning_effort`, `max_completion_tokens` | none…xhigh | live |
| `openrouter` | `openrouter.ai/api/v1` | `reasoning: {effort}` | none…xhigh | live |
| `anthropic` | `api.anthropic.com/v1` | thinking budget (`reasoning_effort` ignored) | budget tokens | vendor docs; test-grade per Anthropic |
| `zai` | `api.z.ai/api/paas/v4` | `thinking: {type}` + level | low, high, max; cannot switch off | vendor docs |
| `deepseek` | `api.deepseek.com` | `thinking: {type}` | default on | vendor docs |
| `gemini` | `generativelanguage.googleapis.com/v1beta/openai` | `reasoning_effort` | minimal, low, medium, high | vendor docs |
| `qwen` | DashScope compatible mode (region-specific) | `enable_thinking` | on/off | vendor docs |
| `xai` | `api.x.ai/v1` | `reasoning_effort` | low, medium, high, xhigh; cannot switch off | vendor docs |
| `meta` | `api.llama.com/compat/v1` | none | — | vendor docs |
| `mistral` | `api.mistral.ai/v1` | `reasoning_effort` | none, high | live |
| `ollama` | `localhost:11434/v1` | `reasoning_effort` | none…max; no `tool_choice` | vendor docs |
| `local` | vLLM, LM Studio, llama.cpp, … | learned | learned | — |
| `custom` | any OpenAI-compatible gateway | learned | learned | — |

In the Verified column, "live" means the preset was checked against a running
endpoint that serves the vendor's models, and "vendor docs" that it follows the
vendor's documentation. Every reply shape Atlas reads has a fixture under
`tests/fixtures/llm/`, written by hand from the documented shape, and the
parser test asserts what Atlas reads from it. Where a reply is thinking:
`reasoning_content` (sglang, DeepSeek, Z.ai, xAI, vLLM with a reasoning
parser, LiteLLM), `reasoning` (vLLM, OpenRouter, Ollama), `reasoning_details`
(OpenRouter), `thinking_blocks` (LiteLLM for Claude and Gemini), `thinking`
chunks inside a content list (Mistral direct), or a leading `<think>…</think>`
block in the content (a server without a reasoning parser). All are read the
same way. DeepSeek's direct endpoint requires the thinking sent back on later
turns once tools are used; that preset does so, no other does.

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
   tell, and a run does (see "When no function call arrives" above).
3. Leave Thinking on Auto and **Save provider**. Then give each role the
   report allows this provider under *Roles in a run* and **Save roles**.

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

Walks you through picking a backend — Telekom LLM Hub, OpenAI, a local/
self-hosted OpenAI-compatible server (vLLM, Ollama, LM Studio, ...), or any
other gateway — collects the base URL/model/key, optionally tests the
connection live before saving, and points every model role (analyst,
reviewer, report, `reason.*`, `dair.*`) at it. Re-run it anytime to register
another backend or reconfigure. Its logic lives in `core/llm_setup.py`,
kept free of any interactive I/O specifically so a future browser dashboard
can drive the same registration/probe/role-assignment calls from a form
instead of a terminal prompt — see that module's docstring.

`bin/atlas provider list` shows what's registered and which role uses what;
`bin/atlas provider use NAME --role ROLE --model ID` repoints an
already-registered provider without the full wizard.

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

The MCP server exposes ~270 tools; shipping every schema each turn would waste
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
`--all-tools` exposes everything up front (~36k tokens of schemas) for
large-context models.

## Rate limits

Providers enforce per-model input/output tokens-per-minute and requests-per-
minute caps. Long investigations resend
a large context each turn, so the input cap is the one you hit. The agent
handles this two ways:

- **Proactive pacing** — the client tracks its own trailing-minute input-token
  spend and sleeps before a request that would exceed
  `ATLAS_AGENT_INPUT_TPM` (default 400000; `0` disables). Set it a little
  under your key's input quota.
- **Patient 429 handling** — a rate-limited response is retried after the wait
  the provider itself suggests (`Retry-After` header or the "try again in N
  seconds" hint in the body), without consuming regular retry attempts, up to
  a total of `ATLAS_AGENT_RATE_LIMIT_WAIT` seconds (default 600).

If you still hit the cap constantly, lower `ATLAS_AGENT_CONTEXT_CHARS`
(derived from the probed window; ~3 000 000 chars for a 1M-token model)
so each turn sends less context.

## Model context auto-probe (LLM check)

At the start of every `atlas run` / `train` / `chat` session Atlas issues a short
`GET /models` against the configured provider, finds the active model id, and
reads a context-window field from the live JSON (`context_length`,
`max_model_len`, nested `top_provider.context_length`, …). There is **no**
local model catalogue. The recommended / default window is **1 000 000 tokens**
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
  On network failure Atlas still installs the 1M recommended window — set
  `ATLAS_MODEL_CONTEXT_TOKENS` if the model is smaller.
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
