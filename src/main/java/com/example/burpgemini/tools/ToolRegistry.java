package com.example.burpgemini.tools;

import com.example.burpgemini.ai.Neutral.ToolSpec;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Declares the tools exposed to the model as provider-neutral {@link ToolSpec}s. Each is a
 * name + description + JSON-Schema (OpenAPI subset) parameters object; each provider translates them
 * into its own wire format (Gemini functionDeclarations, OpenAI tools, …). The declared set is the
 * <em>only</em> way the model can affect a target, and every Tier ≥1 call is mediated before it runs
 * (see {@link RiskTier} and the safety package). There is intentionally no arbitrary shell/OS tool.
 */
public final class ToolRegistry {

    public List<ToolSpec> toolSpecs() {
        List<ToolSpec> d = new ArrayList<>();

        // ---- Tier 0: read-only ---------------------------------------------
        d.add(new ToolSpec("list_proxy_history",
                "List entries from Burp's Proxy HTTP history (already-captured traffic). Read-only.",
                obj(props(
                        p("limit", intType("Max entries to return (default 50).")),
                        p("in_scope_only", boolType("Only entries in Burp scope (default true).")),
                        p("host_contains", strType("Only entries whose host contains this substring.")),
                        p("method", strType("Filter by HTTP method, e.g. GET or POST.")),
                        p("status", intType("Filter by exact response status code."))
                ), req())));

        d.add(new ToolSpec("get_request_response",
                "Fetch the full request and response for one captured item. Read-only.",
                obj(props(
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("id", strType("Item id (from list_proxy_history / get_site_map / get_selected_items).")),
                        p("include_body", boolType("Include bodies (default true).")),
                        p("max_body_bytes", intType("Truncate each body to this many bytes (default 8000)."))
                ), req("source", "id"))));

        d.add(new ToolSpec("get_site_map",
                "List a deduplicated set of endpoints from Burp's Target site map. Read-only.",
                obj(props(
                        p("host_contains", strType("Only endpoints whose host contains this substring.")),
                        p("in_scope_only", boolType("Only in-scope endpoints (default true).")),
                        p("limit", intType("Max endpoints to return (default 200)."))
                ), req())));

        d.add(new ToolSpec("get_selected_items",
                "Return the request(s) the operator attached via right-click 'Send to AI Assistant'. Read-only.",
                obj(props(), req())));

        d.add(new ToolSpec("search_traffic",
                "Search captured requests/responses for a substring and return small snippets. Read-only.",
                obj(props(
                        p("query", strType("Substring to search for.")),
                        p("where", enumType("Search request text, response text, or both (default both).",
                                "request", "response", "both")),
                        p("source", enumType("Corpus to search (default proxy).", "proxy", "sitemap")),
                        p("limit", intType("Max matches to return (default 50)."))
                ), req("query"))));

        d.add(new ToolSpec("get_scope",
                "Report Burp scope status for the hosts seen in captured traffic (isInScope checks). Read-only.",
                obj(props(), req())));

        d.add(new ToolSpec("get_passive_findings",
                "Return recon collected in the background by the passive scanner: the endpoint "
                        + "inventory and deduplicated passive findings (missing headers, sensitive data, "
                        + "CORS/cookie issues, verbose errors, etc.). Read-only.",
                obj(props(
                        p("min_severity", enumType("Only findings at or above this severity (default Info).",
                                "Info", "Low", "Medium", "High")),
                        p("host_contains", strType("Only findings/endpoints whose URL contains this substring.")),
                        p("limit", intType("Max findings to return (default 100)."))
                ), req())));

        d.add(new ToolSpec("get_recon_data",
                "Return the information the passive scanner has gathered from EVERY in-scope request: "
                        + "the parameter inventory (names, types, sample values, endpoints), discovered "
                        + "secrets/tokens (masked), request/response headers, cookies, technologies, hosts "
                        + "and emails. Read-only.",
                obj(props(
                        p("host_contains", strType("Only entries whose URL/endpoint contains this substring.")),
                        p("limit", intType("Max parameters to return (default 200)."))
                ), req())));

        d.add(new ToolSpec("extract_from_captured",
                "Mine an already-captured response (no new traffic) for links, script/JS URLs, API "
                        + "endpoints, HTML/JS comments, forms, emails and likely secrets. Read-only.",
                obj(props(
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("id", strType("Item id whose response body to analyze."))
                ), req("source", "id"))));

        d.add(new ToolSpec("to_curl",
                "Render a captured (or modified) request as a copy-pasteable curl command. Read-only "
                        + "(builds the string; sends nothing).",
                obj(props(
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("id", strType("Item id to render.")),
                        p("base_id", strType("Alternatively, a base id (with base_source) to derive from.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Or a full raw HTTP request to render.")),
                        p("modifications", mutationArray()),
                        p("include_body", boolType("Include the request body (default true)."))
                ), req())));

        d.add(new ToolSpec("decode_transform",
                "Locally decode/encode a string (no target traffic). JWT decode is non-verifying, header/payload only.",
                obj(props(
                        p("data", strType("The string to transform.")),
                        p("operation", enumType("Transform to apply.",
                                "base64_decode", "base64_encode", "url_decode", "url_encode",
                                "html_decode", "jwt_decode_header_payload"))
                ), req("data", "operation"))));

        // ---- Tier 1: confirm, staging only ---------------------------------
        d.add(new ToolSpec("send_to_repeater",
                "Stage a (optionally modified) request in Burp Repeater. Does NOT auto-send. Requires confirmation.",
                obj(props(
                        p("id", strType("Base item id.")),
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("tab_name", strType("Optional Repeater tab name.")),
                        p("modifications", mutationArray())
                ), req("id", "source"))));

        d.add(new ToolSpec("add_to_scope",
                "Add an include rule to Burp scope. Requires confirmation. Do not call unless the operator asks.",
                obj(props(
                        p("url_prefix", strType("URL prefix to include, e.g. https://app.example.com/"))
                ), req("url_prefix"))));

        d.add(new ToolSpec("remove_from_scope",
                "Add an exclude rule to Burp scope. Requires confirmation.",
                obj(props(
                        p("url_prefix", strType("URL prefix to exclude."))
                ), req("url_prefix"))));

        d.add(new ToolSpec("send_to_intruder",
                "Stage an Intruder attack with payload positions. Burp requires manual start. Requires confirmation.",
                obj(props(
                        p("id", strType("Base item id.")),
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("positions", payloadPositionArray()),
                        p("payload_set", arrayOf(strType("A payload value."), "Suggested payloads (staged as a note).")),
                        p("attack_type", enumType("Intruder attack type.",
                                "sniper", "battering_ram", "pitchfork", "cluster_bomb")),
                        p("tab_name", strType("Optional Intruder tab name."))
                ), req("id", "source"))));

        // ---- Tier 2: confirm + warning, sends traffic ----------------------
        d.add(new ToolSpec("send_http_request",
                "Send ONE request (optionally modified) to the target and return the response. "
                        + "Requires confirmation; the operator sees a diff vs. the base request.",
                obj(props(
                        p("base_id", strType("Base item id to derive the target/service from.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional full raw HTTP request to send instead of the base.")),
                        p("modifications", mutationArray())
                ), req())));

        d.add(new ToolSpec("fetch_url",
                "Fetch a single in-scope URL (default GET) and return the response plus extracted "
                        + "links, JS/asset URLs, API endpoints, comments, forms, emails and likely "
                        + "secrets. Requires confirmation (sends one request).",
                obj(props(
                        p("url", strType("Absolute URL to fetch (e.g. https://app.example.com/robots.txt).")),
                        p("method", enumType("HTTP method (default GET).", "GET", "POST", "HEAD", "OPTIONS")),
                        p("max_body_bytes", intType("Truncate the returned body to this many bytes (default 8000)."))
                ), req("url"))));

        d.add(new ToolSpec("start_passive_audit",
                "Run Burp's passive checks over the given captured items and return discovered issues. Requires confirmation.",
                obj(props(
                        p("ids", arrayOf(strType("An item id."), "Item ids to audit.")),
                        p("source", enumType("Where the ids come from.", "proxy", "sitemap", "selection"))
                ), req("ids", "source"))));

        // ---- Tier 3: confirm + strong warning ------------------------------
        d.add(new ToolSpec("start_active_audit",
                "Start an ACTIVE scan (can generate many requests and attack payloads). Runs in the background. "
                        + "Requires strong confirmation.",
                obj(props(
                        p("id", strType("Base item id to seed the audit.")),
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("url", strType("Alternatively, a URL to seed a fresh request for the audit."))
                ), req())));

        d.add(new ToolSpec("fetch_common_paths",
                "Probe a curated list of common recon/misconfiguration paths (robots.txt, sitemap.xml, "
                        + "/.well-known/security.txt, /.git/HEAD, /.env, /actuator, swagger/openapi, "
                        + "/graphql, admin/login, backups, …) on a base URL. Sends many requests — "
                        + "requires strong confirmation. Optionally override the path list.",
                obj(props(
                        p("base_url", strType("Target base URL, e.g. https://app.example.com")),
                        p("paths", arrayOf(strType("A path to probe, e.g. /robots.txt."),
                                "Optional custom path list (defaults to the built-in recon list)."))
                ), req("base_url"))));

        d.add(new ToolSpec("probe_paths",
                "Probe site/API paths on a base URL and classify each (accessible / protected / "
                        + "redirect / missing / error). By default it probes the paths recon and "
                        + "mine_javascript already DISCOVERED for that host — so you hit the real attack "
                        + "surface, not just a wordlist. Safe methods only (GET/HEAD/OPTIONS), in-scope "
                        + "URLs only. Sends many requests — requires strong confirmation. Auto-records "
                        + "accessible/protected sensitive paths as findings.",
                obj(props(
                        p("base_url", strType("Target base URL, e.g. https://app.example.com")),
                        p("paths", arrayOf(strType("A path or absolute URL to probe, e.g. /api/v2/users."),
                                "Optional explicit paths to probe (merged with discovered ones).")),
                        p("use_discovered", boolType("Also probe paths discovered by recon/JS mining for "
                                + "this host (default true).")),
                        p("method", enumType("Safe HTTP method (default GET).", "GET", "HEAD", "OPTIONS")),
                        p("expand_parents", boolType("Also probe parent directories of each path (default false).")),
                        p("check_backups", boolType("Also try backup suffixes (.bak/.old/~/.zip) on file "
                                + "paths (default false).")),
                        p("max", intType("Max probes to send (default 80, max 200).")),
                        p("delay_ms", intType("Delay between probes in ms (default 0)."))
                ), req("base_url"))));

        d.add(new ToolSpec("run_request_sequence",
                "Send a SERIES of crafted requests (e.g. iterate an object id to probe IDOR/BOLA). "
                        + "Requires strong confirmation; the operator sees the count and a sample.",
                obj(props(
                        p("requests", arrayOf(requestSpecSchema(), "Ordered request specs to send.")),
                        p("stop_on_status", intType("Stop the sequence if a response has this status code.")),
                        p("delay_ms", intType("Delay between requests in milliseconds (default 0)."))
                ), req("requests"))));

        // ---- Detection primitives (out-of-band, access control, oracles) ---

        d.add(new ToolSpec("create_oast_payload",
                "Mint a unique Burp Collaborator (OAST) domain/URL to inject into blind sinks "
                        + "(blind SSRF/XXE/RCE/XSS/SQLi). Read-only (no target traffic).",
                obj(props(
                        p("label", strType("Optional label to correlate later callbacks (customData)."))
                ), req())));

        d.add(new ToolSpec("poll_oast_interactions",
                "Poll for out-of-band callbacks (DNS/HTTP/SMTP) received by the Collaborator client. "
                        + "Read-only. Call after injecting an OAST payload.",
                obj(props(
                        p("label", strType("Only interactions matching this label (customData)."))
                ), req())));

        d.add(new ToolSpec("compare_responses",
                "Diff two captured responses (normalized: CSRF tokens/timestamps/ids stripped) — status, "
                        + "length and similarity. Read-only. Powers boolean/access-control reasoning.",
                obj(props(
                        p("a_source", enumType("Source for item A.", "proxy", "sitemap", "selection")),
                        p("a_id", strType("Item A id.")),
                        p("b_source", enumType("Source for item B.", "proxy", "sitemap", "selection")),
                        p("b_id", strType("Item B id."))
                ), req("a_source", "a_id", "b_source", "b_id"))));

        d.add(new ToolSpec("analyze_client_side",
                "Analyze a captured HTML/JS response for DOM-XSS sinks, postMessage handlers, prototype-"
                        + "pollution hints and CSP weaknesses. Read-only.",
                obj(props(
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("id", strType("Item id whose response body to analyze."))
                ), req("source", "id"))));

        d.add(new ToolSpec("mine_javascript",
                "Deep-mine captured JavaScript (no new traffic) for secrets (AWS/GCP/Google/Slack/"
                        + "Stripe/GitHub/GitLab/Twilio/SendGrid/JWT/private keys), API endpoints & "
                        + "fetch/axios call targets, debug/feature flags, DOM-XSS sinks, insecure "
                        + "patterns (disabled TLS/CSRF, weak randomness, hard-coded creds), internal/"
                        + "staging hosts, cloud buckets, GraphQL ops and risky comments — returning a "
                        + "prioritized list of vuln leads to test. Read-only. With no id it sweeps all "
                        + "JS in the proxy history.",
                obj(props(
                        p("source", enumType("Where the id comes from (for a single file).",
                                "proxy", "sitemap", "selection")),
                        p("id", strType("Optional: mine one captured JS item by id. Omit to sweep all JS "
                                + "in the proxy history.")),
                        p("host_contains", strType("When sweeping, only JS whose URL contains this substring.")),
                        p("max_files", intType("Max JS files to mine when sweeping (default 15, max 40)."))
                ), req())));

        d.add(new ToolSpec("report_finding",
                "Record a structured, verified finding (adds it to the AI Recon findings, deduped). "
                        + "Read-only.",
                obj(props(
                        p("type", strType("Vulnerability type, e.g. 'SQL injection (time-based)'.")),
                        p("severity", enumType("Severity.", "Info", "Low", "Medium", "High")),
                        p("confidence", enumType("Confidence.", "Tentative", "Firm", "Certain")),
                        p("url", strType("Affected URL.")),
                        p("evidence", strType("The concrete evidence.")),
                        p("repro", strType("Optional short reproduction steps."))
                ), req("type", "severity", "url", "evidence"))));

        d.add(new ToolSpec("set_identity",
                "Store an auth context (session cookies / bearer token / API key) under a name, for the "
                        + "access-control matrix. Requires confirmation (handles credentials).",
                obj(props(
                        p("name", strType("Identity name, e.g. 'userA' or 'admin'.")),
                        p("headers", objType("Auth headers to apply, e.g. {\"Cookie\":\"...\"} or "
                                + "{\"Authorization\":\"Bearer ...\"}."))
                ), req("name", "headers"))));

        d.add(new ToolSpec("list_identities",
                "List stored identities usable with authz_matrix. Read-only.",
                obj(props(), req())));

        d.add(new ToolSpec("authz_matrix",
                "ACTIVE, authorized-only. Replay a captured request as each stored identity and "
                        + "unauthenticated, and diff responses to flag broken access control (IDOR/BOLA).",
                obj(props(
                        p("base_id", strType("Base item id.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("identities", arrayOf(strType("An identity name."),
                                "Optional subset of identities (default: all stored + unauthenticated)."))
                ), req())));

        d.add(new ToolSpec("test_injection",
                "ACTIVE, authorized-only. Run an oracle-based injection test on a parameter and return a "
                        + "structured result. Classes: ssti (math), sqli_error, sqli_time, sqli_boolean, "
                        + "cmdi_time, path_traversal, oob (blind via OAST).",
                obj(props(
                        p("base_id", strType("Base item id.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional raw request instead of a base id.")),
                        p("param_name", strType("Parameter to inject into.")),
                        p("param_type", enumType("Parameter location (default url).", "url", "body", "cookie", "json", "header")),
                        p("inject_class", enumType("Injection class / oracle.",
                                "ssti", "sqli_error", "sqli_time", "sqli_boolean", "cmdi_time", "path_traversal", "oob")),
                        p("oast_domain", strType("For the 'oob' oracle: the OAST domain from create_oast_payload."))
                ), req("inject_class"))));

        d.add(new ToolSpec("discover_params",
                "ACTIVE, authorized-only. Brute-force hidden parameters and detect which change the "
                        + "response (reflection or a significant diff).",
                obj(props(
                        p("base_id", strType("Base item id.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional raw request instead of a base id.")),
                        p("wordlist", arrayOf(strType("A candidate parameter name."),
                                "Optional custom wordlist (defaults to a built-in list)."))
                ), req())));

        d.add(new ToolSpec("race_requests",
                "ACTIVE, authorized-only. Fire N concurrent copies of a request (race condition / "
                        + "limit-bypass / TOCTOU) and report the status distribution.",
                obj(props(
                        p("base_id", strType("Base item id.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional raw request instead of a base id.")),
                        p("modifications", mutationArray()),
                        p("count", intType("Number of concurrent requests (default 20, max 30)."))
                ), req())));

        // ---- API-specific testing ------------------------------------------

        d.add(new ToolSpec("graphql_introspect",
                "Send a GraphQL introspection query to an endpoint and report whether the schema is "
                        + "exposed (introspection left on in prod maps the whole API). Sends one request — "
                        + "requires confirmation. Point base_id/raw_request at the GraphQL endpoint.",
                obj(props(
                        p("base_id", strType("Base item id (a request to the GraphQL endpoint).")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional raw request instead of a base id."))
                ), req())));

        d.add(new ToolSpec("test_method_tampering",
                "ACTIVE, authorized-only. Replay a request with alternate HTTP verbs (incl. "
                        + "PUT/PATCH/DELETE/TRACE) and method-override headers to find access-control / "
                        + "verb-tampering bypasses. May change state — authorized-only.",
                obj(props(
                        p("base_id", strType("Base item id.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional raw request instead of a base id.")),
                        p("modifications", mutationArray())
                ), req())));

        d.add(new ToolSpec("test_mass_assignment",
                "ACTIVE, authorized-only. Over-post privileged fields (role, is_admin, balance, …) onto "
                        + "a write request (JSON or form) and diff the response to detect mass-assignment / "
                        + "over-posting. Mutates the target object — authorized-only.",
                obj(props(
                        p("base_id", strType("Base item id (ideally a POST/PUT/PATCH write request).")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional raw request instead of a base id.")),
                        p("modifications", mutationArray())
                ), req())));

        return d;
    }

    // ---- shared sub-schemas ------------------------------------------------

    private static JsonObject mutationArray() {
        return arrayOf(mutationSchema(),
                "Ordered modifications applied to the base request.");
    }

    private static JsonObject mutationSchema() {
        return obj(props(
                p("op", enumType("Modification operation.",
                        "set_header", "add_header", "remove_header", "set_body", "set_method",
                        "set_path", "set_query_param", "set_cookie")),
                p("name", strType("Header/parameter/cookie name (when applicable).")),
                p("value", strType("New value (when applicable)."))
        ), req("op"));
    }

    private static JsonObject payloadPositionArray() {
        return arrayOf(obj(props(
                p("where", enumType("Where the payload position sits.",
                        "url_param", "body_param", "header", "cookie", "path")),
                p("name", strType("Parameter/header/cookie name to mark (when applicable)."))
        ), req("where")), "Payload positions to mark.");
    }

    private static JsonObject requestSpecSchema() {
        return obj(props(
                p("base_id", strType("Base item id.")),
                p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                p("raw_request", strType("Optional full raw HTTP request.")),
                p("modifications", mutationArray())
        ), req());
    }

    // ---- tiny JSON-Schema builders -----------------------------------------

    private static JsonObject strType(String desc) {
        return typed("string", desc);
    }

    /** A free-form object (map of string keys to string values). */
    private static JsonObject objType(String desc) {
        JsonObject o = typed("object", desc);
        o.add("additionalProperties", typed("string", null));
        return o;
    }

    private static JsonObject intType(String desc) {
        return typed("integer", desc);
    }

    private static JsonObject boolType(String desc) {
        return typed("boolean", desc);
    }

    private static JsonObject enumType(String desc, String... values) {
        JsonObject o = typed("string", desc);
        JsonArray arr = new JsonArray();
        for (String v : values) {
            arr.add(v);
        }
        o.add("enum", arr);
        return o;
    }

    private static JsonObject typed(String type, String desc) {
        JsonObject o = new JsonObject();
        o.addProperty("type", type);
        if (desc != null) {
            o.addProperty("description", desc);
        }
        return o;
    }

    private static JsonObject arrayOf(JsonObject items, String desc) {
        JsonObject o = new JsonObject();
        o.addProperty("type", "array");
        if (desc != null) {
            o.addProperty("description", desc);
        }
        o.add("items", items);
        return o;
    }

    /** Build an object schema from properties + required list. */
    private static JsonObject obj(JsonObject properties, JsonArray required) {
        JsonObject o = new JsonObject();
        o.addProperty("type", "object");
        o.add("properties", properties);
        if (required != null && required.size() > 0) {
            o.add("required", required);
        }
        return o;
    }

    private static JsonObject props(Prop... entries) {
        JsonObject o = new JsonObject();
        for (Prop e : entries) {
            o.add(e.name, e.schema);
        }
        return o;
    }

    private static Prop p(String name, JsonObject schema) {
        return new Prop(name, schema);
    }

    private static JsonArray req(String... names) {
        JsonArray a = new JsonArray();
        for (String n : names) {
            a.add(n);
        }
        return a;
    }

    private static final class Prop {
        final String name;
        final JsonObject schema;

        Prop(String name, JsonObject schema) {
            this.name = name;
            this.schema = schema;
        }
    }
}
