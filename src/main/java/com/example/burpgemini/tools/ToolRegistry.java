package com.example.burpgemini.tools;

import com.example.burpgemini.gemini.GeminiModels.FunctionDeclaration;
import com.example.burpgemini.gemini.GeminiModels.Tool;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Declares the tools exposed to Gemini as {@code functionDeclarations}. Each declaration is a
 * name + description + JSON-Schema (OpenAPI subset) parameters object. The declared set is the
 * <em>only</em> way the model can affect a target, and every Tier ≥1 call is mediated before it runs
 * (see {@link RiskTier} and the safety package). There is intentionally no arbitrary shell/OS tool.
 */
public final class ToolRegistry {

    /** Wrap all declarations in the single {@code tools[0].functionDeclarations} array Gemini expects. */
    public List<Tool> geminiTools() {
        Tool tool = new Tool();
        tool.functionDeclarations = declarations();
        List<Tool> tools = new ArrayList<>();
        tools.add(tool);
        return tools;
    }

    public List<FunctionDeclaration> declarations() {
        List<FunctionDeclaration> d = new ArrayList<>();

        // ---- Tier 0: read-only ---------------------------------------------
        d.add(new FunctionDeclaration("list_proxy_history",
                "List entries from Burp's Proxy HTTP history (already-captured traffic). Read-only.",
                obj(props(
                        p("limit", intType("Max entries to return (default 50).")),
                        p("in_scope_only", boolType("Only entries in Burp scope (default true).")),
                        p("host_contains", strType("Only entries whose host contains this substring.")),
                        p("method", strType("Filter by HTTP method, e.g. GET or POST.")),
                        p("status", intType("Filter by exact response status code."))
                ), req())));

        d.add(new FunctionDeclaration("get_request_response",
                "Fetch the full request and response for one captured item. Read-only.",
                obj(props(
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("id", strType("Item id (from list_proxy_history / get_site_map / get_selected_items).")),
                        p("include_body", boolType("Include bodies (default true).")),
                        p("max_body_bytes", intType("Truncate each body to this many bytes (default 8000)."))
                ), req("source", "id"))));

        d.add(new FunctionDeclaration("get_site_map",
                "List a deduplicated set of endpoints from Burp's Target site map. Read-only.",
                obj(props(
                        p("host_contains", strType("Only endpoints whose host contains this substring.")),
                        p("in_scope_only", boolType("Only in-scope endpoints (default true).")),
                        p("limit", intType("Max endpoints to return (default 200)."))
                ), req())));

        d.add(new FunctionDeclaration("get_selected_items",
                "Return the request(s) the operator attached via right-click 'Send to AI Assistant'. Read-only.",
                obj(props(), req())));

        d.add(new FunctionDeclaration("search_traffic",
                "Search captured requests/responses for a substring and return small snippets. Read-only.",
                obj(props(
                        p("query", strType("Substring to search for.")),
                        p("where", enumType("Search request text, response text, or both (default both).",
                                "request", "response", "both")),
                        p("source", enumType("Corpus to search (default proxy).", "proxy", "sitemap")),
                        p("limit", intType("Max matches to return (default 50)."))
                ), req("query"))));

        d.add(new FunctionDeclaration("get_scope",
                "Report Burp scope status for the hosts seen in captured traffic (isInScope checks). Read-only.",
                obj(props(), req())));

        d.add(new FunctionDeclaration("decode_transform",
                "Locally decode/encode a string (no target traffic). JWT decode is non-verifying, header/payload only.",
                obj(props(
                        p("data", strType("The string to transform.")),
                        p("operation", enumType("Transform to apply.",
                                "base64_decode", "base64_encode", "url_decode", "url_encode",
                                "html_decode", "jwt_decode_header_payload"))
                ), req("data", "operation"))));

        // ---- Tier 1: confirm, staging only ---------------------------------
        d.add(new FunctionDeclaration("send_to_repeater",
                "Stage a (optionally modified) request in Burp Repeater. Does NOT auto-send. Requires confirmation.",
                obj(props(
                        p("id", strType("Base item id.")),
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("tab_name", strType("Optional Repeater tab name.")),
                        p("modifications", mutationArray())
                ), req("id", "source"))));

        d.add(new FunctionDeclaration("add_to_scope",
                "Add an include rule to Burp scope. Requires confirmation. Do not call unless the operator asks.",
                obj(props(
                        p("url_prefix", strType("URL prefix to include, e.g. https://app.example.com/"))
                ), req("url_prefix"))));

        d.add(new FunctionDeclaration("remove_from_scope",
                "Add an exclude rule to Burp scope. Requires confirmation.",
                obj(props(
                        p("url_prefix", strType("URL prefix to exclude."))
                ), req("url_prefix"))));

        d.add(new FunctionDeclaration("send_to_intruder",
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
        d.add(new FunctionDeclaration("send_http_request",
                "Send ONE request (optionally modified) to the target and return the response. "
                        + "Requires confirmation; the operator sees a diff vs. the base request.",
                obj(props(
                        p("base_id", strType("Base item id to derive the target/service from.")),
                        p("base_source", enumType("Where base_id comes from.", "proxy", "sitemap", "selection")),
                        p("raw_request", strType("Optional full raw HTTP request to send instead of the base.")),
                        p("modifications", mutationArray())
                ), req())));

        d.add(new FunctionDeclaration("start_passive_audit",
                "Run Burp's passive checks over the given captured items and return discovered issues. Requires confirmation.",
                obj(props(
                        p("ids", arrayOf(strType("An item id."), "Item ids to audit.")),
                        p("source", enumType("Where the ids come from.", "proxy", "sitemap", "selection"))
                ), req("ids", "source"))));

        // ---- Tier 3: confirm + strong warning ------------------------------
        d.add(new FunctionDeclaration("start_active_audit",
                "Start an ACTIVE scan (can generate many requests and attack payloads). Runs in the background. "
                        + "Requires strong confirmation.",
                obj(props(
                        p("id", strType("Base item id to seed the audit.")),
                        p("source", enumType("Where the id comes from.", "proxy", "sitemap", "selection")),
                        p("url", strType("Alternatively, a URL to seed a fresh request for the audit."))
                ), req())));

        d.add(new FunctionDeclaration("run_request_sequence",
                "Send a SERIES of crafted requests (e.g. iterate an object id to probe IDOR/BOLA). "
                        + "Requires strong confirmation; the operator sees the count and a sample.",
                obj(props(
                        p("requests", arrayOf(requestSpecSchema(), "Ordered request specs to send.")),
                        p("stop_on_status", intType("Stop the sequence if a response has this status code.")),
                        p("delay_ms", intType("Delay between requests in milliseconds (default 0)."))
                ), req("requests"))));

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
