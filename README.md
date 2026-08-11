# Burp AI Assistant (Gemini / Puter)

A Burp Suite extension (Java, Montoya API) that embeds an AI assistant to support
**authorized, in‑scope penetration testing only**. Pick your backend with a switch:

- **Google Gemini** — the `generateContent` REST API with **your own API key**.
- **Puter AI** — Puter's **OpenAI‑compatible** endpoint (proxies GPT / Claude / Gemini / Grok) with
  a **Puter auth token**.
- **Custom** — **any** OpenAI‑compatible provider (OpenAI, OpenRouter, Groq, DeepSeek, Mistral, xAI,
  …), auto‑configured from the [models.dev](https://models.dev) catalog with your own API key.

The design is built around one rule:

> **The AI proposes, the human confirms, the extension executes.**
> The model never sends traffic itself — it *requests* tools, and the extension runs them only after
> you approve, and only after a scope check. Passive analysis of already‑captured traffic is free;
> anything that touches a target is gated.

Both providers are called directly with **your own key/token** — it does **not** use Burp's native
`ai` package or Burp AI credits. The safety gating is provider‑independent.

> ⚠️ **For authorized testing only.** Use this against systems you have explicit permission to test.
> The confirmation gates and scope enforcement are core to the design, not optional polish.

---

## Features

- **Chat tab ("AI Assistant")** — talk to Gemini about captured traffic; it analyses requests and
  responses for likely vulnerability classes with an explicit *confidence* and *severity* for each
  finding.
- **Right‑click context actions** in Proxy, Repeater, Target, Intruder, and the embedded browser —
  **Add to AI Assistant context** (accumulate multiple requests over time), **Set as AI context
  (replace)**, and one‑click **Analyze with AI** / **Explain this request/response with AI**. The
  chat shows a chip with the attached count (hover to list them).
- **Copy chat / Copy reply / Regenerate** buttons; click the context chip to **remove individual
  attached requests**. **Export report** (Markdown) from the AI Recon tab.
- **🤖 Auto‑hunt (autonomous assessment)** — one click turns the AI loose on an in‑scope target:
  it fetches `robots.txt` / `sitemap.xml` / `/.well-known/security.txt`, probes common
  misconfig/exposure paths (`.git`, `.env`, `/actuator`, swagger/openapi, `/graphql`, admin, backups),
  fetches the page + its JavaScript and **mines the HTML/JS** for endpoints, hard‑coded secrets and
  revealing comments, reasons about vulnerability classes, and proves the most promising issues with
  the smallest safe test — reporting findings as it goes. (Enable **⚡ Agent mode** for a fully
  hands‑off run.)
- **Proactive agent loop** — the model actively drives Burp: recon (history/site map/search),
  fetching pages/JS and extracting artifacts, passive audits, fetching live responses via
  `send_http_request`, and crafting the smallest safe active test to confirm an issue.
  **Quick‑action** buttons kick off common tasks in one click.
- **Risk tiering + confirmation cards** — Tier 0 (read‑only) runs automatically; Tier 1–3 render an
  Approve/Deny card showing the target, scope status, a request **diff** (or request count/sample),
  the risk tier, and the model's rationale. Tier 3 is **always** confirmed, even if the global
  confirmation toggle is off.
- **⚡ Agent mode (auto‑approve)** — optional hands‑off mode that auto‑approves every action so the
  assistant runs end‑to‑end. Scope still blocks out‑of‑scope traffic; a loud banner shows while it's
  on, and every action is still logged as a tool card.
- **Background passive recon ("AI Recon" tab)** — a read‑only passive scanner mines **every**
  in‑scope proxied request/response. It **gathers information** (parameter inventory with sample
  values, discovered secrets/tokens (masked), request/response headers, cookies, technologies, hosts,
  emails) that keeps accumulating across repeat requests, **plus** deduplicated security findings
  (missing headers, insecure cookies, CORS misconfig, JWT/secret exposure, verbose errors, reflected
  params, …) with recurrence counts. Different paths are tracked as different endpoints. The chat AI
  reads it via `get_recon_data` and `get_passive_findings`. Optional, throttled **AI enrichment** can
  add a deeper pass on new endpoints.
- **Web search (Puter)** — Puter's built‑in `web_search` tool is enabled for OpenAI models, so the
  assistant can pull real‑time info into its analysis.
- **Model specs from [models.dev](https://models.dev)** — the Config tab can load up‑to‑date model
  metadata (context window, input/output pricing, tool‑call & reasoning support) to populate the
  model dropdowns and show a one‑line spec for the selected model.
- **🎨 AI Appearance tab** — animated backgrounds (aurora, starfield, matrix rain, bubbles, plasma,
  gradient, or a custom image) with readable, contrast‑checked controls; optionally **re‑theme all
  of Burp** to match (every tab's colours adapt, text stays legible), with a **Reset to normal Burp**
  button that restores the default theme.
- **Scope enforcement** — out‑of‑scope target traffic is blocked by default; overriding requires an
  explicit setting *and* a per‑action checkbox.
- **No arbitrary shell/OS tool** — the model can only affect a target through the mediated HTTP/Burp
  tools.

---

## Prebuilt JAR

A ready‑to‑load, shaded JAR is checked in at **[`dist/burp-gemini-assistant.jar`](dist/burp-gemini-assistant.jar)** —
download it and skip straight to *[Load into Burp](#load-into-burp)*. To rebuild it yourself, follow
the steps below.

## Build

Prerequisites: **JDK 17+** (the project targets Java 17 bytecode; it builds fine on a newer JDK).

```bash
./gradlew shadowJar
```

The loadable, self‑contained (fat/shaded) JAR is written to:

```
build/libs/burp-gemini-assistant.jar
```

Gson is bundled and relocated (`com.example.burpgemini.shaded.gson`) so it can't clash with Burp or
another extension. The Montoya API is `compileOnly` (provided by Burp at runtime), so it is **not**
bundled.

---

## Load into Burp

1. **Extensions → Installed → Add.**
2. **Extension type:** Java.
3. Select `build/libs/burp-gemini-assistant.jar`.
4. Four tabs appear: **AI Assistant** (chat), **AI Recon** (live passive findings + endpoint
   inventory), **AI Appearance** (animated backgrounds + Burp re‑theme), and **AI Assistant Config**
   (settings).

---

## Choose a provider & set credentials

Open the **AI Assistant Config** tab and pick **AI provider**. The form greys out the fields for the
provider you're not using. Then **Save** and click **Test connection** (a bad key/token reports the
exact error). Click **Refresh models (models.dev)** to pull up‑to‑date model specs & pricing from
[models.dev](https://models.dev) — the model dropdowns are populated from the catalog and a one‑line
spec (context window · input/output $ per 1M · tools/reasoning/vision) is shown for the selected
model. (This is loaded best‑effort in the background on open; the button forces a refresh.)

### Option A — Google Gemini
1. Create a key at **https://aistudio.google.com/apikey**.
2. Paste it into **Gemini API key**, pick a **Gemini model** and **Thinking level**, **Save**.
3. Or set the `GEMINI_API_KEY` environment variable and leave the field blank (never persisted).

### Option B — Puter AI (OpenAI‑compatible)
1. Sign in at **https://puter.com/dashboard**, open the **API tokens** section, click **Create token**.
2. Paste it into **Puter auth token**, choose a **Puter model** (default `gpt-5.3-chat`; also
   `gpt-5.4-nano`, `gpt-5.4`, `gpt-5.6-luna/terra/sol`, `gpt-5.3-codex`, `openai/gpt-oss-120b`, … —
   the field is editable), leave **Enable web search** on if you like, **Save**.
3. Or set the `PUTER_AUTH_TOKEN` environment variable and leave the field blank.

Puter exposes an **OpenAI‑compatible** Chat Completions endpoint
(`https://api.puter.com/puterai/openai/v1/chat/completions`), so tool/function calling works through
the standard OpenAI convention. **Web search:** for OpenAI models, the extension adds Puter's built‑in
`{ "type": "web_search" }` tool so the model can fetch up‑to‑date info (toggle in Config). Switching
providers starts a fresh chat session (the two wire formats aren't interchangeable mid‑conversation).

> **Puter and multi‑turn tool calling.** Puter proxies many models through the OpenAI‑*Responses*
> bridge, whose `call_id` linkage breaks when structured tool history is resent
> (`No tool call found for … call_id …`). To stay robust across **all** Puter models (including
> reasoning models like the GPT‑5.6 family), this extension represents *prior* tool exchanges as
> plain text while still advertising the tools each turn, so the model keeps calling them. Gemini
> (Option A) uses native structured tool calling.

### Option C — Custom (any OpenAI‑compatible provider, via models.dev)
Pick **AI provider → Custom** to use **any** OpenAI‑compatible provider — OpenAI, OpenRouter, Groq,
DeepSeek, Mistral, xAI, Together, Fireworks, …

1. Click **Refresh models (models.dev)** so the catalog loads.
2. Choose a provider from the **models.dev provider** dropdown. The **Endpoint URL** and **Model**
   list auto‑fill from the catalog (the key's env‑var name is shown as a hint).
3. Paste the provider's **API key**, tweak the endpoint/model if needed, **Save**, **Test connection**.

The endpoint is the provider's OpenAI‑compatible `…/chat/completions` URL and auth is a standard
`Authorization: Bearer <key>` header. You can also set the endpoint/model by hand without picking a
models.dev provider. (Native‑only APIs such as raw Anthropic or raw Google aren't OpenAI‑compatible —
reach those through Gemini (Option A) or an OpenAI‑compatible gateway like OpenRouter/Puter.)

> **Secrets note:** saved keys/tokens live in Burp's preferences, which are **not strongly encrypted
> at rest**. They are never logged and never written into chat transcripts. Prefer the environment
> variables if you don't want them persisted.

### Settings

| Setting | Default | Effect |
|---|---|---|
| AI provider | Google Gemini | Switch between Gemini and Puter AI. |
| Gemini model | `gemini-3.1-pro-preview-customtools` | Model used when the provider is Gemini. |
| Thinking level | High | Reasoning depth (`thinkingConfig.thinkingBudget`: High = dynamic, Low = minimal). |
| Puter auth token | — | Bearer token for Puter's OpenAI‑compatible endpoint. |
| Puter model | `gpt-5.3-chat` | Model used when the provider is Puter (editable). |
| Puter web search | **ON** | Adds Puter's built‑in `web_search` tool for OpenAI models. |
| ⚡ Agent mode (auto‑approve) | **OFF** | Auto‑approves **every** action with no dialog, so the assistant runs end‑to‑end on its own. Scope still applies (out‑of‑scope stays blocked unless you also enable the override). A loud red banner shows while it's on. |
| Background passive scan | **ON** | Local heuristic checks on proxied responses → the AI Recon tab + `get_passive_findings`. |
| Passive scan in‑scope only | **ON** | Restrict passive scanning to in‑scope traffic. |
| AI‑enrich new endpoints | **OFF** | Optional throttled AI pass over newly‑seen endpoints (uses tokens). |
| Require confirmation before active actions | **ON** | Governs Tier 1–2. Tier 3 always confirms regardless. |
| Respect Burp scope | **ON** | Blocks out‑of‑scope target traffic. |
| Allow out‑of‑scope with explicit confirmation | **OFF** | If ON, out‑of‑scope actions can proceed only after ticking a red per‑action checkbox. |
| Persist chat transcripts | OFF | (Reserved) Transcripts never contain secrets. |

When a safety toggle is relaxed, a persistent warning banner appears at the top of the chat tab.

---

## Usage walkthrough

1. **Set your key** in the Config tab (above).
2. In **Proxy → HTTP history** (or Repeater/Target/Intruder), right‑click one or more requests →
   **Add to AI Assistant context** (repeat to attach several), or **Analyze with AI** /
   **Explain … with AI** to attach and ask in one click. A context chip shows the attached count.
3. Open the **AI Assistant** tab and ask, e.g.
   *"Check this login request for auth bypass"* or *"Is the `id` parameter vulnerable to IDOR?"*
   Press **Send** (or Ctrl/Cmd+Enter). Or use a **quick action** button —
   **🔍 Passive recon**, **🎯 Analyze selection**, **🛡 Security headers** — to kick off a
   canned agent task in one click.
4. The assistant analyses the traffic and **proactively drives Burp** — it will call
   `send_http_request` to fetch a live response (e.g. when a selected item has no response yet),
   run `start_passive_audit` for recon, and craft the smallest safe active test to confirm an issue:
   - **Tier 0** (read history/site map/selection, search, decode) runs immediately.
   - **Tier 1–3** show a confirmation card — review the target, scope status, and the request diff or
     count, then **Approve** or **Deny**. Denials (with an optional reason) are fed back to the model
     so it can adapt.
   - With **⚡ Agent mode** on (Config tab), those actions are **auto‑approved** and the assistant
     runs the whole investigation end‑to‑end. The tool cards still show every action as an audit
     trail, and out‑of‑scope targets are still blocked.
5. Results appear inline as **tool‑call cards** (Pending → Running → Result/Denied/Blocked), giving a
   visible audit trail. The same events are logged to the extension's Output tab.
6. Use **Cancel** to abort an in‑flight turn, or **Clear chat** to start a new session.

### Background passive recon
While you browse the target through Burp, the **AI Recon** tab fills up on its own. The passive
scanner reads **every** in‑scope response (it sends nothing) and populates five views:
**Findings** (deduplicated, with a recurrence count), **Endpoints** (each distinct path tracked
separately), **Parameters** (names, types, and sample values that accumulate across requests),
**Secrets / Tokens** (masked JWTs/keys/bearer tokens and where they were seen), and
**Headers / Tech / Hosts**. Click **Analyze in chat** to have the assistant call `get_recon_data`
and `get_passive_findings`, prioritise everything, and suggest next steps. Toggle passive scanning
(and optional AI enrichment) in the Config tab.

---

## Tool catalog & risk tiers

| Tool | Tier | Notes |
|---|---|---|
| `list_proxy_history`, `get_request_response`, `get_site_map`, `get_selected_items`, `search_traffic`, `get_scope`, `get_passive_findings`, `get_recon_data`, `extract_from_captured`, `decode_transform` | **0 — auto** | Read‑only / local. No dialog. `get_recon_data` returns the gathered parameter/secret/header/cookie/tech inventory; `extract_from_captured` mines an already‑captured response for links/JS/endpoints/secrets. |
| `send_to_repeater`, `add_to_scope`, `remove_from_scope`, `send_to_intruder` | **1 — confirm** | Stage in a Burp tool / edit scope. No new target traffic. Intruder is staged (Burp's API can't auto‑start an attack); set payloads and start it manually. |
| `send_http_request`, `start_passive_audit`, `fetch_url` | **2 — confirm + warning** | Sends one request / runs passive checks. `fetch_url` fetches a URL and auto‑extracts links/JS/endpoints/secrets. |
| `start_active_audit`, `run_request_sequence`, `fetch_common_paths` | **3 — confirm + strong warning** | Active scan / a series of requests / probing many recon paths. Card shows the count and a sample; **always** confirmed. |

Unknown/unmapped tools default to Tier 3 (fail safe).

---

## How it works (architecture)

```
ChatTab ─▶ ChatController (agent loop) ─▶ AiProvider ─▶ Gemini generateContent
   ▲            │  1. send neutral history + tool specs        └▶ Puter (OpenAI chat/completions)
   │            │  2. model replies with text and/or tool call(s)
   │            │  3. per call: RiskTier → ScopeGuard → ConfirmationManager → ToolExecutor
   └ tool cards ┘  4. feed each result back, loop until text‑only
```

The conversation is kept in a **provider‑neutral** message model; each provider translates it to/from
its own wire format, so the same agent loop and the same safety gating drive either backend.

Key files:

- `BurpGeminiExtension` — entry point (`BurpExtension#initialize`); builds the providers, registers
  tabs, the context‑menu action, and an unloading handler that stops the thread pool.
- `chat/ChatController` — the agent loop over neutral history; comments call out tiering + scope.
- `ai/AiProvider` + `ai/Neutral` — the provider interface and neutral conversation model.
- `ai/GeminiProvider` — Gemini `generateContent`; preserves each `thoughtSignature` so tool calls work.
- `ai/OpenAiCompatibleProvider` — Puter's OpenAI‑compatible endpoint (tools / tool_calls).
- `ai/HttpTransport` — shared cancellable POST with retries/backoff (429/5xx/network).
- `ai/ModelsCatalog` — fetches & parses the [models.dev](https://models.dev) `api.json` catalog for
  model specs/pricing used by the Config tab.
- `recon/PassiveScanner` — Proxy response handler running local heuristic checks (read‑only);
  `recon/FindingsStore` holds the deduplicated findings + endpoint inventory; `recon/ReconTab` is the
  live view; `recon/AiEnricher` is the optional throttled AI pass.
- `tools/ToolRegistry` — the neutral tool specs (name + description + JSON‑Schema params).
- `tools/ToolExecutor` — maps tool calls to Montoya operations; token‑efficient JSON results.
- `tools/RiskTier` — tier enum + tool→tier policy (fails safe).
- `safety/ScopeGuard` — `isInScope` checks + override policy.
- `safety/ConfirmationManager` — approval policy; `chat/ToolCard` renders the Approve/Deny card.
- `gemini/SystemPrompt` — the embedded system prompt (analysis vs. gated active testing; hard limits).

All Gemini/tool/scan work runs off the Swing EDT on a small thread pool; UI updates are marshalled
back with `SwingUtilities.invokeLater`. An in‑flight turn is cancellable.

---

## Dependencies

| Dependency | Version | Scope |
|---|---|---|
| `net.portswigger.burp.extensions:montoya-api` | 2026.7 | compileOnly (provided by Burp) |
| `com.google.code.gson:gson` | 2.11.0 | bundled + relocated |
| Gradle Shadow plugin (`com.gradleup.shadow`) | 8.3.6 | build |
| HTTP client | JDK `java.net.http.HttpClient` | no extra dependency |

---

## Notes & limitations

- **Intruder / active start:** Montoya exposes no programmatic *start* of an Intruder attack, so
  `send_to_intruder` stages the attack and asks you to start it manually (which is why it's Tier 1).
- **Scope enumeration:** Burp's API cannot list scope rules, only test a URL. `get_scope` therefore
  reports `isInScope()` for the hosts seen in captured traffic.
- **Active audits** run in the background — watch Burp's Dashboard/Scanner for progress and issues.
- **Model names** are provided as of the build's target date; aliases `gemini-flash-latest` /
  `gemini-pro-latest` track the newest of each line.
