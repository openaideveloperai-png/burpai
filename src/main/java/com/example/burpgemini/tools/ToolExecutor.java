package com.example.burpgemini.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.example.burpgemini.recon.FindingsStore;
import com.example.burpgemini.recon.PassiveFinding;
import com.example.burpgemini.util.BurpContext;
import com.example.burpgemini.util.TextDiff;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps a Gemini function call (name + args) to concrete Montoya operations and returns a compact,
 * token-efficient JSON result that becomes the {@code functionResponse}.
 *
 * <p>Tier ≥1 tools are only invoked here <em>after</em> the confirmation gate and scope guard have
 * approved them — this class does not re-check policy, it executes. It also exposes small helpers
 * ({@link #targetUrlsFor}, {@link #describeAction}, {@link #payloadDetailFor}, {@link #countInfoFor})
 * so the controller can populate the confirmation card without duplicating request-building logic.
 */
public final class ToolExecutor {

    private final BurpContext ctx;
    private final MontoyaApi api;
    private final FindingsStore findings;

    public ToolExecutor(BurpContext ctx, FindingsStore findings) {
        this.ctx = ctx;
        this.api = ctx.api();
        this.findings = findings;
    }

    /** A resolved captured item, normalised across proxy/sitemap/selection sources. */
    private static final class Item {
        HttpRequest request;
        HttpResponse response; // may be null
        String url;
    }

    // ------------------------------------------------------------------ dispatch

    public JsonObject execute(String tool, JsonObject args) {
        try {
            switch (tool) {
                case "list_proxy_history":
                    return listProxyHistory(args);
                case "get_request_response":
                    return getRequestResponse(args);
                case "get_site_map":
                    return getSiteMap(args);
                case "get_selected_items":
                    return getSelectedItems();
                case "search_traffic":
                    return searchTraffic(args);
                case "get_scope":
                    return getScope();
                case "get_passive_findings":
                    return getPassiveFindings(args);
                case "decode_transform":
                    return decodeTransform(args);
                case "send_to_repeater":
                    return sendToRepeater(args);
                case "add_to_scope":
                    return addToScope(args);
                case "remove_from_scope":
                    return removeFromScope(args);
                case "send_to_intruder":
                    return sendToIntruder(args);
                case "send_http_request":
                    return sendHttpRequest(args);
                case "start_passive_audit":
                    return startPassiveAudit(args);
                case "start_active_audit":
                    return startActiveAudit(args);
                case "run_request_sequence":
                    return runRequestSequence(args);
                default:
                    return error("Unknown tool: " + tool);
            }
        } catch (Exception e) {
            ctx.logError("Tool '" + tool + "' failed: " + e, e);
            return error("Tool execution error: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ Tier 0

    private JsonObject listProxyHistory(JsonObject args) {
        int limit = getInt(args, "limit", 50);
        boolean inScopeOnly = getBool(args, "in_scope_only", true);
        String hostContains = getStr(args, "host_contains", null);
        String method = getStr(args, "method", null);
        Integer status = args.has("status") && !args.get("status").isJsonNull()
                ? args.get("status").getAsInt() : null;

        JsonArray items = new JsonArray();
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int count = 0;
        for (ProxyHttpRequestResponse h : history) {
            if (count >= limit) {
                break;
            }
            String url = safeUrl(h);
            String reqHost = hostOf(h);
            String reqMethod = methodOf(h);
            if (inScopeOnly && !isInScope(url)) {
                continue;
            }
            if (hostContains != null && !reqHost.contains(hostContains)) {
                continue;
            }
            if (method != null && !method.equalsIgnoreCase(reqMethod)) {
                continue;
            }
            int st = h.hasResponse() && h.response() != null ? h.response().statusCode() : 0;
            if (status != null && st != status) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("id", String.valueOf(h.id()));
            o.addProperty("method", reqMethod);
            o.addProperty("url", url);
            o.addProperty("host", reqHost);
            o.addProperty("status", st);
            o.addProperty("mime", h.mimeType() == null ? "" : h.mimeType().toString());
            o.addProperty("length", h.hasResponse() && h.response() != null ? h.response().body().length() : 0);
            o.addProperty("time", h.time() == null ? "" : h.time().toString());
            items.add(o);
            count++;
        }
        JsonObject r = new JsonObject();
        r.add("items", items);
        r.addProperty("returned", items.size());
        r.addProperty("total_history", history.size());
        return r;
    }

    private JsonObject getRequestResponse(JsonObject args) {
        String source = getStr(args, "source", "proxy");
        String id = getStr(args, "id", null);
        boolean includeBody = getBool(args, "include_body", true);
        int maxBody = getInt(args, "max_body_bytes", 8000);

        Item item = resolve(source, id);
        if (item == null) {
            return error("No item found for source=" + source + " id=" + id);
        }
        JsonObject r = new JsonObject();
        r.addProperty("url", item.url);
        r.addProperty("request_headers", headersToString(item.request.headers(), item.request.toString()));
        if (includeBody) {
            addTruncated(r, "request_body", item.request.bodyToString(), maxBody);
        }
        if (item.response != null) {
            r.addProperty("status", item.response.statusCode());
            r.addProperty("mime", item.response.mimeType() == null ? "" : item.response.mimeType().toString());
            r.addProperty("response_headers", headersToStringResp(item.response));
            if (includeBody) {
                addTruncated(r, "response_body", item.response.bodyToString(), maxBody);
            }
        } else {
            r.addProperty("status", 0);
            r.addProperty("note", "No response captured for this item.");
        }
        return r;
    }

    private JsonObject getSiteMap(JsonObject args) {
        String hostContains = getStr(args, "host_contains", null);
        boolean inScopeOnly = getBool(args, "in_scope_only", true);
        int limit = getInt(args, "limit", 200);

        Map<String, JsonObject> byUrl = new LinkedHashMap<>();
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            String url = urlOf(rr);
            if (url.isEmpty()) {
                continue;
            }
            if (inScopeOnly && !isInScope(url)) {
                continue;
            }
            if (hostContains != null) {
                HttpService svc = rr.httpService();
                if (svc == null || !svc.host().contains(hostContains)) {
                    continue;
                }
            }
            JsonObject entry = byUrl.get(url);
            if (entry == null) {
                if (byUrl.size() >= limit) {
                    continue;
                }
                entry = new JsonObject();
                entry.addProperty("url", url);
                entry.add("methods_seen", new JsonArray());
                entry.add("status_seen", new JsonArray());
                byUrl.put(url, entry);
            }
            addUnique(entry.getAsJsonArray("methods_seen"), rr.request() == null ? "" : rr.request().method());
            if (rr.hasResponse() && rr.response() != null) {
                addUnique(entry.getAsJsonArray("status_seen"), String.valueOf(rr.response().statusCode()));
            }
        }
        JsonArray arr = new JsonArray();
        byUrl.values().forEach(arr::add);
        JsonObject r = new JsonObject();
        r.add("endpoints", arr);
        r.addProperty("returned", arr.size());
        return r;
    }

    private JsonObject getSelectedItems() {
        JsonArray arr = new JsonArray();
        List<HttpRequestResponse> items = ctx.contextItems();
        for (int i = 0; i < items.size(); i++) {
            HttpRequestResponse rr = items.get(i);
            JsonObject o = new JsonObject();
            o.addProperty("id", String.valueOf(i));
            o.addProperty("source", "selection");
            o.addProperty("url", urlOf(rr));
            if (rr.request() != null) {
                o.addProperty("method", rr.request().method());
            }
            if (rr.hasResponse() && rr.response() != null) {
                o.addProperty("status", rr.response().statusCode());
            }
            arr.add(o);
        }
        JsonObject r = new JsonObject();
        r.add("items", arr);
        r.addProperty("count", arr.size());
        if (arr.size() == 0) {
            r.addProperty("note", "No items attached. Ask the operator to right-click a request "
                    + "and choose 'Send to AI Assistant'.");
        }
        return r;
    }

    private JsonObject searchTraffic(JsonObject args) {
        String query = getStr(args, "query", null);
        if (query == null || query.isBlank()) {
            return error("query is required");
        }
        String where = getStr(args, "where", "both");
        String source = getStr(args, "source", "proxy");
        int limit = getInt(args, "limit", 50);

        JsonArray matches = new JsonArray();
        int count = 0;

        if ("sitemap".equals(source)) {
            List<HttpRequestResponse> list = api.siteMap().requestResponses();
            for (int i = 0; i < list.size() && count < limit; i++) {
                HttpRequestResponse rr = list.get(i);
                JsonObject m = matchIn(query, where,
                        rr.request() == null ? null : rr.request().toString(),
                        rr.hasResponse() && rr.response() != null ? rr.response().toString() : null);
                if (m != null) {
                    m.addProperty("source", "sitemap");
                    m.addProperty("id", String.valueOf(i));
                    m.addProperty("url", urlOf(rr));
                    matches.add(m);
                    count++;
                }
            }
        } else {
            List<ProxyHttpRequestResponse> list = api.proxy().history();
            for (ProxyHttpRequestResponse h : list) {
                if (count >= limit) {
                    break;
                }
                JsonObject m = matchIn(query, where,
                        h.request() == null ? null : h.request().toString(),
                        h.hasResponse() && h.response() != null ? h.response().toString() : null);
                if (m != null) {
                    m.addProperty("source", "proxy");
                    m.addProperty("id", String.valueOf(h.id()));
                    m.addProperty("url", safeUrl(h));
                    matches.add(m);
                    count++;
                }
            }
        }
        JsonObject r = new JsonObject();
        r.add("matches", matches);
        r.addProperty("returned", matches.size());
        return r;
    }

    private JsonObject getScope() {
        // Montoya exposes isInScope(url) but cannot enumerate scope rules. Report scope status for
        // the distinct hosts seen in captured traffic, which is what the model actually needs.
        Map<String, String> hostToUrl = new LinkedHashMap<>();
        for (ProxyHttpRequestResponse h : api.proxy().history()) {
            String host = hostOf(h);
            if (!host.isEmpty() && !hostToUrl.containsKey(host)) {
                hostToUrl.put(host, safeUrl(h));
            }
        }
        for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
            HttpService svc = rr.httpService();
            if (svc != null && !hostToUrl.containsKey(svc.host())) {
                hostToUrl.put(svc.host(), urlOf(rr));
            }
        }
        JsonArray arr = new JsonArray();
        for (Map.Entry<String, String> e : hostToUrl.entrySet()) {
            JsonObject o = new JsonObject();
            o.addProperty("host", e.getKey());
            o.addProperty("sample_url", e.getValue());
            o.addProperty("in_scope", isInScope(e.getValue()));
            arr.add(o);
        }
        JsonObject r = new JsonObject();
        r.add("hosts", arr);
        r.addProperty("note", "Burp's API cannot enumerate scope rules; these are isInScope() checks "
                + "for hosts seen in traffic.");
        return r;
    }

    private JsonObject getPassiveFindings(JsonObject args) {
        String minSev = getStr(args, "min_severity", "Info");
        String hostContains = getStr(args, "host_contains", null);
        int limit = getInt(args, "limit", 100);
        int minRank = severityRank(minSev);

        JsonArray f = new JsonArray();
        int shown = 0;
        for (PassiveFinding pf : findings.findingsSnapshot()) {
            if (pf.severityRank() < minRank) {
                continue;
            }
            if (hostContains != null && (pf.url == null || !pf.url.contains(hostContains))) {
                continue;
            }
            if (shown >= limit) {
                break;
            }
            JsonObject o = new JsonObject();
            o.addProperty("severity", pf.severity);
            o.addProperty("confidence", pf.confidence);
            o.addProperty("type", pf.type);
            o.addProperty("url", pf.url);
            o.addProperty("evidence", pf.evidence);
            o.addProperty("source", pf.ai ? "ai" : "heuristic");
            f.add(o);
            shown++;
        }

        JsonArray eps = new JsonArray();
        int epCount = 0;
        for (FindingsStore.EndpointInfo e : findings.endpointsSnapshot()) {
            if (hostContains != null && (e.sampleUrl == null || !e.sampleUrl.contains(hostContains))) {
                continue;
            }
            if (epCount >= 200) {
                break;
            }
            JsonObject o = new JsonObject();
            o.addProperty("url", e.sampleUrl);
            o.add("methods", toStrArray(e.methods));
            o.add("statuses", toIntArray(e.statuses));
            o.addProperty("hits", e.hits.get());
            eps.add(o);
            epCount++;
        }

        JsonObject r = new JsonObject();
        r.addProperty("finding_count", findings.findingCount());
        r.addProperty("endpoint_count", findings.endpointCount());
        r.add("findings", f);
        r.add("endpoints", eps);
        if (findings.findingCount() == 0 && findings.endpointCount() == 0) {
            r.addProperty("note", "Nothing collected yet. The passive scanner records in-scope proxy "
                    + "traffic — browse the target through Burp, or check that passive scanning is "
                    + "enabled and the target is in scope.");
        }
        return r;
    }

    private static int severityRank(String sev) {
        switch (sev == null ? "" : sev) {
            case "High":
                return 4;
            case "Medium":
                return 3;
            case "Low":
                return 2;
            default:
                return 1;
        }
    }

    private static JsonArray toStrArray(java.util.Collection<String> c) {
        JsonArray a = new JsonArray();
        for (String s : c) {
            a.add(s);
        }
        return a;
    }

    private static JsonArray toIntArray(java.util.Collection<Integer> c) {
        JsonArray a = new JsonArray();
        for (Integer i : c) {
            a.add(i);
        }
        return a;
    }

    private JsonObject decodeTransform(JsonObject args) {
        String data = getStr(args, "data", "");
        String op = getStr(args, "operation", "");
        JsonObject r = new JsonObject();
        r.addProperty("operation", op);
        try {
            switch (op) {
                case "base64_decode":
                    r.addProperty("result", new String(decodeBase64Lenient(data), StandardCharsets.UTF_8));
                    break;
                case "base64_encode":
                    r.addProperty("result", Base64.getEncoder()
                            .encodeToString(data.getBytes(StandardCharsets.UTF_8)));
                    break;
                case "url_decode":
                    r.addProperty("result", URLDecoder.decode(data, StandardCharsets.UTF_8));
                    break;
                case "url_encode":
                    r.addProperty("result", URLEncoder.encode(data, StandardCharsets.UTF_8));
                    break;
                case "html_decode":
                    r.addProperty("result", htmlDecode(data));
                    break;
                case "jwt_decode_header_payload":
                    return jwtDecode(data);
                default:
                    return error("Unknown operation: " + op);
            }
        } catch (Exception e) {
            return error("Transform failed: " + e.getMessage());
        }
        return r;
    }

    // ------------------------------------------------------------------ Tier 1

    private JsonObject sendToRepeater(JsonObject args) {
        Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
        if (item == null) {
            return error("Base item not found.");
        }
        HttpRequest req = applyMutations(item.request, args.getAsJsonArray("modifications"));
        String tab = getStr(args, "tab_name", null);
        if (tab != null && !tab.isBlank()) {
            api.repeater().sendToRepeater(req, tab);
        } else {
            api.repeater().sendToRepeater(req);
        }
        JsonObject r = new JsonObject();
        r.addProperty("staged", true);
        r.addProperty("tab_name", tab == null ? "(auto)" : tab);
        r.addProperty("method", req.method());
        r.addProperty("url", req.url());
        r.addProperty("note", "Staged in Repeater. Not sent — the operator sends it manually.");
        return r;
    }

    private JsonObject addToScope(JsonObject args) {
        String prefix = getStr(args, "url_prefix", null);
        if (prefix == null || prefix.isBlank()) {
            return error("url_prefix is required");
        }
        api.scope().includeInScope(prefix);
        JsonObject r = new JsonObject();
        r.addProperty("added", true);
        r.addProperty("url_prefix", prefix);
        return r;
    }

    private JsonObject removeFromScope(JsonObject args) {
        String prefix = getStr(args, "url_prefix", null);
        if (prefix == null || prefix.isBlank()) {
            return error("url_prefix is required");
        }
        api.scope().excludeFromScope(prefix);
        JsonObject r = new JsonObject();
        r.addProperty("excluded", true);
        r.addProperty("url_prefix", prefix);
        return r;
    }

    private JsonObject sendToIntruder(JsonObject args) {
        Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
        if (item == null) {
            return error("Base item not found.");
        }
        HttpRequest req = item.request;
        List<Range> offsets = insertionOffsets(req, args.getAsJsonArray("positions"));
        String tab = getStr(args, "tab_name", null);
        int marked = offsets.size();
        if (marked > 0) {
            HttpRequestTemplate template = HttpRequestTemplate.httpRequestTemplate(req, offsets);
            if (tab != null && !tab.isBlank()) {
                api.intruder().sendToIntruder(req.httpService(), template, tab);
            } else {
                api.intruder().sendToIntruder(req.httpService(), template);
            }
        } else {
            if (tab != null && !tab.isBlank()) {
                api.intruder().sendToIntruder(req, tab);
            } else {
                api.intruder().sendToIntruder(req);
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("staged", true);
        r.addProperty("positions_marked", marked);
        r.addProperty("attack_type", getStr(args, "attack_type", "sniper"));
        JsonArray payloads = args.has("payload_set") && args.get("payload_set").isJsonArray()
                ? args.getAsJsonArray("payload_set") : new JsonArray();
        r.addProperty("payload_set_size", payloads.size());
        r.addProperty("url", req.url());
        r.addProperty("note", "Staged in Intruder. Burp's API cannot auto-start an attack — set the "
                + "payload list and start it manually. Suggested payloads are echoed back for reference.");
        r.add("suggested_payloads", payloads);
        return r;
    }

    // ------------------------------------------------------------------ Tier 2

    private JsonObject sendHttpRequest(JsonObject args) {
        HttpRequest req;
        try {
            req = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        long start = System.nanoTime();
        HttpRequestResponse rr = api.http().sendRequest(req);
        long ms = (System.nanoTime() - start) / 1_000_000L;

        JsonObject r = new JsonObject();
        r.addProperty("url", req.url());
        r.addProperty("method", req.method());
        r.addProperty("timing_ms", ms);
        if (rr.response() != null) {
            HttpResponse resp = rr.response();
            r.addProperty("status", resp.statusCode());
            r.addProperty("reason", resp.reasonPhrase());
            r.addProperty("mime", resp.mimeType() == null ? "" : resp.mimeType().toString());
            r.addProperty("response_headers", headersToStringResp(resp));
            addTruncated(r, "response_body", resp.bodyToString(), 8000);
        } else {
            r.addProperty("status", 0);
            r.addProperty("note", "No response received.");
        }
        return r;
    }

    private JsonObject startPassiveAudit(JsonObject args) {
        String source = getStr(args, "source", "proxy");
        JsonArray ids = args.has("ids") && args.get("ids").isJsonArray()
                ? args.getAsJsonArray("ids") : new JsonArray();
        Audit audit = api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS));
        int added = 0;
        for (JsonElement idEl : ids) {
            Item item = resolve(source, idEl.getAsString());
            if (item == null) {
                continue;
            }
            if (item.response != null) {
                audit.addRequestResponse(
                        HttpRequestResponse.httpRequestResponse(item.request, item.response));
            } else {
                audit.addRequest(item.request);
            }
            added++;
        }
        // Passive checks complete quickly; poll briefly for issues.
        for (int i = 0; i < 8; i++) {
            if (audit.requestCount() >= added && audit.insertionPointCount() >= 0) {
                if (!audit.issues().isEmpty()) {
                    break;
                }
            }
            sleepQuietly(500);
        }
        JsonArray issues = issuesToJson(audit.issues());
        String status = audit.statusMessage();
        audit.delete();

        JsonObject r = new JsonObject();
        r.addProperty("items_audited", added);
        r.addProperty("status", status);
        r.add("issues", issues);
        r.addProperty("issue_count", issues.size());
        return r;
    }

    // ------------------------------------------------------------------ Tier 3

    private JsonObject startActiveAudit(JsonObject args) {
        Audit audit = api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
        String url = getStr(args, "url", null);
        String seededUrl;
        if (url != null && !url.isBlank()) {
            audit.addRequest(HttpRequest.httpRequestFromUrl(url));
            seededUrl = url;
        } else {
            Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
            if (item == null) {
                return error("Provide a url, or a valid id/source to seed the active audit.");
            }
            audit.addRequest(item.request);
            seededUrl = item.url;
        }
        JsonObject r = new JsonObject();
        r.addProperty("started", true);
        r.addProperty("seed_url", seededUrl);
        r.addProperty("status", audit.statusMessage());
        r.addProperty("note", "Active scan is running in the background. Watch Burp's Dashboard / "
                + "Scanner for progress and issues; it may generate many requests.");
        return r;
    }

    private JsonObject runRequestSequence(JsonObject args) {
        JsonArray specs = args.getAsJsonArray("requests");
        Integer stopOn = args.has("stop_on_status") && !args.get("stop_on_status").isJsonNull()
                ? args.get("stop_on_status").getAsInt() : null;
        int delay = getInt(args, "delay_ms", 0);

        JsonArray results = new JsonArray();
        boolean stoppedEarly = false;
        int sent = 0;
        for (JsonElement el : specs) {
            HttpRequest req;
            try {
                req = buildRequestFromSpec(el.getAsJsonObject());
            } catch (IllegalArgumentException e) {
                JsonObject ro = new JsonObject();
                ro.addProperty("index", sent);
                ro.addProperty("error", e.getMessage());
                results.add(ro);
                continue;
            }
            HttpRequestResponse rr = api.http().sendRequest(req);
            int status = rr.response() != null ? rr.response().statusCode() : 0;
            JsonObject ro = new JsonObject();
            ro.addProperty("index", sent);
            ro.addProperty("url", req.url());
            ro.addProperty("method", req.method());
            ro.addProperty("status", status);
            ro.addProperty("length", rr.response() != null ? rr.response().body().length() : 0);
            results.add(ro);
            sent++;
            if (stopOn != null && status == stopOn) {
                stoppedEarly = true;
                break;
            }
            if (delay > 0) {
                sleepQuietly(delay);
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("sent", sent);
        r.addProperty("stopped_early", stoppedEarly);
        r.add("results", results);
        return r;
    }

    // ------------------------------------------------------------------ confirmation-card helpers

    /** Best-effort target URL(s) for the confirmation card and scope check. */
    public List<String> targetUrlsFor(String tool, JsonObject args) {
        List<String> urls = new ArrayList<>();
        try {
            switch (tool) {
                case "send_http_request": {
                    HttpRequest req = buildRequestFromSpec(args);
                    urls.add(req.url());
                    break;
                }
                case "run_request_sequence": {
                    for (JsonElement el : args.getAsJsonArray("requests")) {
                        try {
                            urls.add(buildRequestFromSpec(el.getAsJsonObject()).url());
                        } catch (RuntimeException ignored) {
                            // skip unresolvable spec for the URL list
                        }
                    }
                    break;
                }
                case "start_active_audit": {
                    String url = getStr(args, "url", null);
                    if (url != null && !url.isBlank()) {
                        urls.add(url);
                    } else {
                        Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
                        if (item != null) {
                            urls.add(item.url);
                        }
                    }
                    break;
                }
                case "start_passive_audit": {
                    String source = getStr(args, "source", "proxy");
                    if (args.has("ids") && args.get("ids").isJsonArray()) {
                        for (JsonElement idEl : args.getAsJsonArray("ids")) {
                            Item item = resolve(source, idEl.getAsString());
                            if (item != null) {
                                urls.add(item.url);
                            }
                        }
                    }
                    break;
                }
                case "send_to_repeater":
                case "send_to_intruder": {
                    Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
                    if (item != null) {
                        urls.add(item.url);
                    }
                    break;
                }
                case "add_to_scope":
                case "remove_from_scope":
                    urls.add(getStr(args, "url_prefix", ""));
                    break;
                default:
                    break;
            }
        } catch (RuntimeException e) {
            // fall through — return whatever we collected
        }
        return urls;
    }

    /** Whether a tool actually sends new traffic to a target (and therefore needs a scope gate). */
    public boolean isTargetFacing(String tool) {
        switch (tool) {
            case "send_http_request":
            case "start_active_audit":
            case "run_request_sequence":
            case "start_passive_audit":
                return true;
            default:
                return false;
        }
    }

    public String describeAction(String tool, JsonObject args) {
        switch (tool) {
            case "send_to_repeater":
                return "Stage a request in Repeater (not sent).";
            case "add_to_scope":
                return "Add an include rule to Burp scope: " + getStr(args, "url_prefix", "");
            case "remove_from_scope":
                return "Add an exclude rule to Burp scope: " + getStr(args, "url_prefix", "");
            case "send_to_intruder":
                return "Stage an Intruder attack (manual start required).";
            case "send_http_request":
                return "Send ONE HTTP request to the target and read the response.";
            case "start_passive_audit":
                return "Run Burp passive checks over selected captured items.";
            case "start_active_audit":
                return "Start an ACTIVE Burp scan against the target (can send many requests).";
            case "run_request_sequence":
                return "Send a SERIES of crafted requests to the target.";
            default:
                return tool;
        }
    }

    /** Diff (send_http_request) or request sample (sequence) for the confirmation card; may be null. */
    public String payloadDetailFor(String tool, JsonObject args) {
        try {
            if ("send_http_request".equals(tool)) {
                HttpRequest base = baseRequestForDiff(args);
                HttpRequest fin = buildRequestFromSpec(args);
                if (base != null) {
                    return TextDiff.unified(base.toString(), fin.toString());
                }
                return "Outgoing request:\n" + truncate(fin.toString(), 1500);
            }
            if ("run_request_sequence".equals(tool)) {
                JsonArray specs = args.getAsJsonArray("requests");
                StringBuilder sb = new StringBuilder();
                if (specs.size() > 0) {
                    sb.append("First request:\n")
                      .append(truncate(buildRequestFromSpec(specs.get(0).getAsJsonObject()).toString(), 1200));
                    if (specs.size() > 1) {
                        sb.append("\n\nLast request:\n")
                          .append(truncate(buildRequestFromSpec(
                                  specs.get(specs.size() - 1).getAsJsonObject()).toString(), 1200));
                    }
                }
                return sb.toString();
            }
            if ("send_to_intruder".equals(tool)) {
                Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
                if (item != null) {
                    int n = insertionOffsets(item.request, args.getAsJsonArray("positions")).size();
                    return "Payload positions marked: " + n + "\nBase request:\n"
                            + truncate(item.request.toString(), 1200);
                }
            }
        } catch (RuntimeException e) {
            return "(could not render payload preview: " + e.getMessage() + ")";
        }
        return null;
    }

    public String countInfoFor(String tool, JsonObject args) {
        if ("run_request_sequence".equals(tool) && args.has("requests")) {
            int n = args.getAsJsonArray("requests").size();
            String stop = args.has("stop_on_status") ? ", stop on HTTP " + args.get("stop_on_status").getAsInt() : "";
            int delay = getInt(args, "delay_ms", 0);
            return n + " request(s)" + stop + (delay > 0 ? ", " + delay + "ms apart" : "");
        }
        if ("start_active_audit".equals(tool)) {
            return "Active scan — count is open-ended (Burp decides how many requests to send).";
        }
        return null;
    }

    // ------------------------------------------------------------------ request building

    private HttpRequest baseRequestForDiff(JsonObject args) {
        String baseId = getStr(args, "base_id", null);
        String baseSource = getStr(args, "base_source", "proxy");
        if (baseId != null) {
            Item item = resolve(baseSource, baseId);
            return item == null ? null : item.request;
        }
        return null;
    }

    /**
     * Build the final request for send_http_request / a sequence spec from
     * {base_id, base_source, raw_request, modifications}.
     */
    private HttpRequest buildRequestFromSpec(JsonObject spec) {
        String baseId = getStr(spec, "base_id", null);
        String baseSource = getStr(spec, "base_source", "proxy");
        String raw = getStr(spec, "raw_request", null);

        HttpRequest base = null;
        if (baseId != null) {
            Item item = resolve(baseSource, baseId);
            if (item != null) {
                base = item.request;
            }
        }

        HttpRequest req;
        if (raw != null && !raw.isBlank()) {
            HttpService service;
            if (base != null) {
                service = base.httpService();
            } else {
                service = serviceFromRaw(raw);
            }
            if (service == null) {
                throw new IllegalArgumentException(
                        "raw_request needs a target: supply base_id/base_source, or include a Host header.");
            }
            req = HttpRequest.httpRequest(service, raw);
        } else if (base != null) {
            req = base;
        } else {
            throw new IllegalArgumentException(
                    "Provide base_id + base_source, or a raw_request.");
        }
        return applyMutations(req, spec.has("modifications") ? spec.getAsJsonArray("modifications") : null);
    }

    private HttpRequest applyMutations(HttpRequest req, JsonArray mods) {
        if (mods == null) {
            return req;
        }
        for (JsonElement el : mods) {
            JsonObject m = el.getAsJsonObject();
            String op = getStr(m, "op", "");
            String name = getStr(m, "name", null);
            String value = getStr(m, "value", "");
            switch (op) {
                case "set_header":
                    req = req.hasHeader(name) ? req.withUpdatedHeader(name, value)
                            : req.withAddedHeader(name, value);
                    break;
                case "add_header":
                    req = req.withAddedHeader(name, value);
                    break;
                case "remove_header":
                    req = req.withRemovedHeader(name);
                    break;
                case "set_body":
                    req = req.withBody(value);
                    break;
                case "set_method":
                    req = req.withMethod(value);
                    break;
                case "set_path":
                    req = req.withPath(value);
                    break;
                case "set_query_param":
                    req = req.withParameter(HttpParameter.urlParameter(name, value));
                    break;
                case "set_cookie":
                    req = req.withParameter(HttpParameter.cookieParameter(name, value));
                    break;
                default:
                    // Unknown op: skip (self-healing loop can correct via the error surfaced elsewhere).
                    break;
            }
        }
        return req;
    }

    private HttpService serviceFromRaw(String raw) {
        for (String line : raw.split("\r\n|\n")) {
            String lower = line.toLowerCase();
            if (lower.startsWith("host:")) {
                String host = line.substring(5).trim();
                int port = -1;
                boolean secure = true;
                int colon = host.lastIndexOf(':');
                if (colon > -1 && colon < host.length() - 1) {
                    try {
                        port = Integer.parseInt(host.substring(colon + 1).trim());
                        host = host.substring(0, colon).trim();
                    } catch (NumberFormatException ignored) {
                        // host had no numeric port
                    }
                }
                if (port == 80) {
                    secure = false;
                }
                if (port == -1) {
                    return HttpService.httpService(host, 443, true);
                }
                return HttpService.httpService(host, port, secure);
            }
            if (line.isBlank()) {
                break; // reached end of headers
            }
        }
        return null;
    }

    /** Locate payload-position ranges in the request bytes (approximate, ASCII offsets). */
    private List<Range> insertionOffsets(HttpRequest req, JsonArray positions) {
        List<Range> ranges = new ArrayList<>();
        if (positions == null) {
            return ranges;
        }
        String text = req.toString();
        for (JsonElement el : positions) {
            JsonObject p = el.getAsJsonObject();
            String where = getStr(p, "where", "");
            String name = getStr(p, "name", null);
            Range r = locate(text, where, name);
            if (r != null) {
                ranges.add(r);
            }
        }
        return ranges;
    }

    private Range locate(String text, String where, String name) {
        try {
            if ("header".equals(where) && name != null) {
                int idx = indexOfLineStart(text, name + ":");
                if (idx >= 0) {
                    int valStart = text.indexOf(':', idx) + 1;
                    while (valStart < text.length() && text.charAt(valStart) == ' ') {
                        valStart++;
                    }
                    int valEnd = text.indexOf('\r', valStart);
                    if (valEnd < 0) {
                        valEnd = text.indexOf('\n', valStart);
                    }
                    if (valEnd < 0) {
                        valEnd = text.length();
                    }
                    return Range.range(valStart, valEnd);
                }
                return null;
            }
            if (name != null) {
                // url_param / body_param / cookie: find name=value
                String needle = name + "=";
                int idx = text.indexOf(needle);
                if (idx >= 0) {
                    int valStart = idx + needle.length();
                    int valEnd = valStart;
                    while (valEnd < text.length()) {
                        char c = text.charAt(valEnd);
                        if (c == '&' || c == ';' || c == ' ' || c == '\r' || c == '\n') {
                            break;
                        }
                        valEnd++;
                    }
                    return Range.range(valStart, valEnd);
                }
            }
            if ("path".equals(where)) {
                int start = text.indexOf(' ') + 1;
                int end = text.indexOf(' ', start);
                if (start > 0 && end > start) {
                    return Range.range(start, end);
                }
            }
        } catch (RuntimeException ignored) {
            // best-effort; unresolved positions are simply not marked
        }
        return null;
    }

    private int indexOfLineStart(String text, String prefix) {
        int from = 0;
        while (true) {
            int idx = text.indexOf(prefix, from);
            if (idx < 0) {
                return -1;
            }
            if (idx == 0 || text.charAt(idx - 1) == '\n') {
                return idx;
            }
            from = idx + 1;
        }
    }

    // ------------------------------------------------------------------ resolution & JSON helpers

    private Item resolve(String source, String id) {
        if (id == null) {
            return null;
        }
        source = source == null ? "proxy" : source;
        try {
            switch (source) {
                case "proxy": {
                    for (ProxyHttpRequestResponse h : api.proxy().history()) {
                        if (String.valueOf(h.id()).equals(id)) {
                            return item(h.request(), h.response(), safeUrl(h));
                        }
                    }
                    return null;
                }
                case "sitemap": {
                    List<HttpRequestResponse> list = api.siteMap().requestResponses();
                    int idx = Integer.parseInt(id);
                    if (idx >= 0 && idx < list.size()) {
                        HttpRequestResponse rr = list.get(idx);
                        return item(rr.request(), rr.response(), urlOf(rr));
                    }
                    return null;
                }
                case "selection": {
                    List<HttpRequestResponse> list = ctx.contextItems();
                    int idx = Integer.parseInt(id);
                    if (idx >= 0 && idx < list.size()) {
                        HttpRequestResponse rr = list.get(idx);
                        return item(rr.request(), rr.response(), urlOf(rr));
                    }
                    return null;
                }
                default:
                    return null;
            }
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Item item(HttpRequest req, HttpResponse resp, String url) {
        if (req == null) {
            return null;
        }
        Item it = new Item();
        it.request = req;
        it.response = resp;
        it.url = url != null ? url : req.url();
        return it;
    }

    private boolean isInScope(String url) {
        if (url == null) {
            return false;
        }
        try {
            return api.scope().isInScope(url);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String safeUrl(ProxyHttpRequestResponse h) {
        return h.request() != null ? h.request().url() : "";
    }

    private static String urlOf(HttpRequestResponse rr) {
        return rr.request() != null ? rr.request().url() : "";
    }

    private static String hostOf(ProxyHttpRequestResponse h) {
        if (h.request() != null && h.request().httpService() != null) {
            return h.request().httpService().host();
        }
        return "";
    }

    private static String methodOf(ProxyHttpRequestResponse h) {
        return h.request() != null ? h.request().method() : "";
    }

    private JsonObject matchIn(String query, String where, String requestText, String responseText) {
        boolean inReq = ("request".equals(where) || "both".equals(where))
                && requestText != null && requestText.contains(query);
        boolean inResp = ("response".equals(where) || "both".equals(where))
                && responseText != null && responseText.contains(query);
        if (!inReq && !inResp) {
            return null;
        }
        JsonObject m = new JsonObject();
        m.addProperty("where", inReq ? "request" : "response");
        String hay = inReq ? requestText : responseText;
        m.addProperty("snippet", snippet(hay, query));
        return m;
    }

    private static String snippet(String hay, String query) {
        int idx = hay.indexOf(query);
        int start = Math.max(0, idx - 40);
        int end = Math.min(hay.length(), idx + query.length() + 40);
        String s = hay.substring(start, end).replace("\r", " ").replace("\n", " ");
        return (start > 0 ? "…" : "") + s + (end < hay.length() ? "…" : "");
    }

    private JsonArray issuesToJson(List<AuditIssue> issues) {
        JsonArray arr = new JsonArray();
        for (AuditIssue issue : issues) {
            JsonObject o = new JsonObject();
            o.addProperty("name", issue.name());
            o.addProperty("severity", issue.severity() == null ? "" : issue.severity().name());
            o.addProperty("confidence", issue.confidence() == null ? "" : issue.confidence().name());
            o.addProperty("url", issue.baseUrl());
            arr.add(o);
        }
        return arr;
    }

    private static void addTruncated(JsonObject r, String field, String value, int maxBytes) {
        if (value == null) {
            value = "";
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= maxBytes) {
            r.addProperty(field, value);
            r.addProperty(field + "_truncated", false);
        } else {
            r.addProperty(field, truncate(value, maxBytes));
            r.addProperty(field + "_truncated", true);
            r.addProperty(field + "_total_bytes", bytes.length);
        }
    }

    private static String headersToString(List<HttpHeader> headers, String fallbackRequestText) {
        if (headers == null || headers.isEmpty()) {
            // Fall back to the request line + headers portion of the raw text.
            int bodyStart = fallbackRequestText.indexOf("\r\n\r\n");
            return bodyStart > 0 ? fallbackRequestText.substring(0, bodyStart) : fallbackRequestText;
        }
        StringBuilder sb = new StringBuilder();
        for (HttpHeader h : headers) {
            sb.append(h.name()).append(": ").append(h.value()).append('\n');
        }
        return sb.toString().stripTrailing();
    }

    private static String headersToStringResp(HttpResponse resp) {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP ").append(resp.statusCode()).append(' ')
          .append(resp.reasonPhrase() == null ? "" : resp.reasonPhrase()).append('\n');
        for (HttpHeader h : resp.headers()) {
            sb.append(h.name()).append(": ").append(h.value()).append('\n');
        }
        return sb.toString().stripTrailing();
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…[truncated]";
    }

    private static void addUnique(JsonArray arr, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        for (JsonElement el : arr) {
            if (el.getAsString().equals(value)) {
                return;
            }
        }
        arr.add(value);
    }

    private static byte[] decodeBase64Lenient(String data) {
        String s = data.trim();
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return Base64.getUrlDecoder().decode(padBase64(s.replace('+', '-').replace('/', '_')));
        }
    }

    private static String padBase64(String s) {
        int rem = s.length() % 4;
        if (rem == 0) {
            return s;
        }
        return s + "====".substring(rem);
    }

    private JsonObject jwtDecode(String data) {
        String[] parts = data.trim().split("\\.");
        if (parts.length < 2) {
            return error("Not a JWT (expected at least header.payload).");
        }
        JsonObject r = new JsonObject();
        r.addProperty("header", new String(Base64.getUrlDecoder()
                .decode(padBase64(parts[0])), StandardCharsets.UTF_8));
        r.addProperty("payload", new String(Base64.getUrlDecoder()
                .decode(padBase64(parts[1])), StandardCharsets.UTF_8));
        r.addProperty("signature_present", parts.length >= 3 && !parts[2].isEmpty());
        r.addProperty("note", "Signature NOT verified. Header/payload only.");
        return r;
    }

    private static String htmlDecode(String s) {
        return s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
                .replace("&#39;", "'").replace("&#x27;", "'").replace("&apos;", "'")
                .replace("&nbsp;", " ").replace("&amp;", "&");
    }

    // ---- primitive arg getters ---------------------------------------------

    private static String getStr(JsonObject o, String key, String def) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return def;
        }
        JsonElement e = o.get(key);
        return e.isJsonPrimitive() ? e.getAsString() : def;
    }

    private static int getInt(JsonObject o, String key, int def) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return def;
        }
        try {
            return o.get(key).getAsInt();
        } catch (RuntimeException e) {
            return def;
        }
    }

    private static boolean getBool(JsonObject o, String key, boolean def) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return def;
        }
        try {
            return o.get(key).getAsBoolean();
        } catch (RuntimeException e) {
            return def;
        }
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static JsonObject error(String message) {
        JsonObject o = new JsonObject();
        o.addProperty("error", message);
        return o;
    }
}
