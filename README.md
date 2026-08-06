# Burp Gemini Assistant

A Burp Suite extension (Java, Montoya API) that embeds a **Google Gemini** assistant to support
**authorized, in‑scope penetration testing only**.

The design is built around one rule:

> **The AI proposes, the human confirms, the extension executes.**
> The model never sends traffic itself — it *requests* tools, and the extension runs them only after
> you approve, and only after a scope check. Passive analysis of already‑captured traffic is free;
> anything that touches a target is gated.

It calls the Gemini REST API directly with **your own API key** — it does **not** use Burp's native
`ai` package or Burp AI credits.

> ⚠️ **For authorized testing only.** Use this against systems you have explicit permission to test.
> The confirmation gates and scope enforcement are core to the design, not optional polish.

---

## Features

- **Chat tab ("AI Assistant")** — talk to Gemini about captured traffic; it analyses requests and
  responses for likely vulnerability classes with an explicit *confidence* and *severity* for each
  finding.
- **Right‑click → "Send to AI Assistant"** in Proxy, Repeater, Target, Intruder, and the embedded
  browser — attaches the selected request(s) as context.
- **Function‑calling agent loop** — the model can call a fixed catalog of tools; every call is risk‑
  tiered and mediated.
- **Risk tiering + confirmation cards** — Tier 0 (read‑only) runs automatically; Tier 1–3 render an
  Approve/Deny card showing the target, scope status, a request **diff** (or request count/sample),
  the risk tier, and the model's rationale. Tier 3 is **always** confirmed, even if the global
  confirmation toggle is off.
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
4. Two tabs appear: **AI Assistant** (chat) and **AI Assistant Config** (settings).

---

## Get & set a Gemini API key

1. Create a key at **https://aistudio.google.com/apikey**.
2. Open the **AI Assistant Config** tab, paste the key, click **Save**, then **Test connection**.
   - You should see *"OK — Gemini responded successfully"*. A bad key reports the exact error.
3. Alternatively, set the `GEMINI_API_KEY` environment variable before launching Burp and leave the
   field blank — the extension uses it as a fallback so the secret is never persisted.

> **Secrets note:** if you Save the key, it is stored in Burp's preferences, which are **not strongly
> encrypted at rest**. The key is never logged and never written into chat transcripts.

### Settings

| Setting | Default | Effect |
|---|---|---|
| Model | `gemini-3.1-pro-preview-customtools` | The custom‑tools variant prioritises the declared tools for reliable function calling. |
| Thinking level | High | Gemini 3 uses `thinking_level` (Low = fast/cheap, High = deep) instead of temperature/top‑p/top‑k. |
| Require confirmation before active actions | **ON** | Governs Tier 1–2. Tier 3 always confirms regardless. |
| Respect Burp scope | **ON** | Blocks out‑of‑scope target traffic. |
| Allow out‑of‑scope with explicit confirmation | **OFF** | If ON, out‑of‑scope actions can proceed only after ticking a red per‑action checkbox. |
| Persist chat transcripts | OFF | (Reserved) Transcripts never contain the API key. |

When a safety toggle is relaxed, a persistent warning banner appears at the top of the chat tab.

---

## Usage walkthrough

1. **Set your key** in the Config tab (above).
2. In **Proxy → HTTP history** (or Repeater/Target/Intruder), right‑click a request →
   **Send to AI Assistant**. A *"context attached"* chip appears in the chat tab.
3. Open the **AI Assistant** tab and ask, e.g.
   *"Check this login request for auth bypass"* or *"Is the `id` parameter vulnerable to IDOR?"*
   Press **Send** (or Ctrl/Cmd+Enter).
4. The assistant analyses the traffic and, when a quick check would settle a question, **requests a
   tool**:
   - **Tier 0** (read history/site map/selection, search, decode) runs immediately.
   - **Tier 1–3** show a confirmation card. Review the target, scope status, and the request diff or
     count, then **Approve** or **Deny**. Denials (with an optional reason) are fed back to the model
     so it can adapt.
5. Results appear inline as **tool‑call cards** (Pending → Running → Result/Denied/Blocked), giving a
   visible audit trail. The same events are logged to the extension's Output tab.
6. Use **Cancel** to abort an in‑flight turn, or **Clear chat** to start a new session.

---

## Tool catalog & risk tiers

| Tool | Tier | Notes |
|---|---|---|
| `list_proxy_history`, `get_request_response`, `get_site_map`, `get_selected_items`, `search_traffic`, `get_scope`, `decode_transform` | **0 — auto** | Read‑only / local. No dialog. |
| `send_to_repeater`, `add_to_scope`, `remove_from_scope`, `send_to_intruder` | **1 — confirm** | Stage in a Burp tool / edit scope. No new target traffic. Intruder is staged (Burp's API can't auto‑start an attack); set payloads and start it manually. |
| `send_http_request`, `start_passive_audit` | **2 — confirm + warning** | Sends one request / runs passive checks. Card shows a request **diff**. |
| `start_active_audit`, `run_request_sequence` | **3 — confirm + strong warning** | Active scan / a series of crafted requests. Card shows the count and a sample; **always** confirmed. |

Unknown/unmapped tools default to Tier 3 (fail safe).

---

## How it works (architecture)

```
ChatTab  ──▶  ChatController (the agent loop)  ──▶  GeminiClient  ──▶  Gemini generateContent
   ▲               │  1. send history + tool declarations
   │               │  2. model replies with text and/or functionCall(s)
   │               │  3. per call: RiskTier → ScopeGuard → ConfirmationManager → ToolExecutor
   └── tool cards ◀┘  4. feed each result back as functionResponse, loop until text‑only
```

Key files:

- `BurpGeminiExtension` — entry point (`BurpExtension#initialize`); registers tabs, the context‑menu
  action, and an unloading handler that stops the thread pool.
- `chat/ChatController` — the agent loop; comments call out the tiering and scope enforcement.
- `gemini/GeminiClient` — `generateContent` REST calls, retries/backoff (401/403/429/5xx), cancellation.
- `tools/ToolRegistry` — the function declarations (JSON‑Schema) sent to Gemini.
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
