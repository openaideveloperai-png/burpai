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
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.params.HttpParameterType;
import com.example.burpgemini.hunt.IdentityStore;
import com.example.burpgemini.hunt.OastManager;
import com.example.burpgemini.hunt.Payloads;
import com.example.burpgemini.recon.FindingsStore;
import com.example.burpgemini.recon.InfoStore;
import com.example.burpgemini.recon.PassiveFinding;
import com.example.burpgemini.util.BurpContext;
import com.example.burpgemini.util.ContentExtractor;
import com.example.burpgemini.util.JsMiner;
import com.example.burpgemini.util.ResponseDiff;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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
    private final InfoStore info;
    private final OastManager oast;
    private final IdentityStore identities;

    public ToolExecutor(BurpContext ctx, FindingsStore findings, InfoStore info,
                        OastManager oast, IdentityStore identities) {
        this.ctx = ctx;
        this.api = ctx.api();
        this.findings = findings;
        this.info = info;
        this.oast = oast;
        this.identities = identities;
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
                case "get_recon_data":
                    return getReconData(args);
                case "extract_from_captured":
                    return extractFromCaptured(args);
                case "analyze_client_side":
                    return analyzeClientSide(args);
                case "mine_javascript":
                    return mineJavascript(args);
                case "fetch_url":
                    return fetchUrl(args);
                case "fetch_common_paths":
                    return fetchCommonPaths(args);
                case "probe_paths":
                    return probePaths(args);
                case "create_oast_payload":
                    return createOastPayload(args);
                case "poll_oast_interactions":
                    return pollOastInteractions(args);
                case "compare_responses":
                    return compareResponses(args);
                case "set_identity":
                    return setIdentity(args);
                case "list_identities":
                    return listIdentities();
                case "authz_matrix":
                    return authzMatrix(args);
                case "test_injection":
                    return testInjection(args);
                case "discover_params":
                    return discoverParams(args);
                case "race_requests":
                    return raceRequests(args);
                case "graphql_introspect":
                    return graphqlIntrospect(args);
                case "test_method_tampering":
                    return testMethodTampering(args);
                case "test_mass_assignment":
                    return testMassAssignment(args);
                case "report_finding":
                    return reportFinding(args);
                case "decode_transform":
                    return decodeTransform(args);
                case "to_curl":
                    return toCurl(args);
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
            o.addProperty("occurrences", pf.occurrences);
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

    private JsonObject getReconData(JsonObject args) {
        String hostContains = getStr(args, "host_contains", null);
        int limit = getInt(args, "limit", 200);

        JsonArray params = new JsonArray();
        int pn = 0;
        for (InfoStore.Param p : info.paramsSnapshot()) {
            if (pn >= limit) {
                break;
            }
            if (hostContains != null && p.endpoints.stream().noneMatch(e -> e.contains(hostContains))) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("name", p.name);
            o.add("types", toStrArray(p.types));
            o.add("sample_values", toStrArray(p.samples));
            o.add("endpoints", toStrArray(p.endpoints));
            o.addProperty("hits", p.count.get());
            params.add(o);
            pn++;
        }

        JsonArray secrets = new JsonArray();
        for (InfoStore.Secret s : info.secretsSnapshot()) {
            if (hostContains != null && s.urls.stream().noneMatch(u -> u.contains(hostContains))) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("kind", s.kind);
            o.addProperty("masked_value", s.masked);
            o.add("seen_at", toStrArray(s.urls));
            secrets.add(o);
        }

        JsonObject r = new JsonObject();
        r.addProperty("param_count", info.paramCount());
        r.addProperty("secret_count", info.secretCount());
        r.add("parameters", params);
        r.add("secrets", secrets);
        r.add("request_headers", headerStats(info.reqHeadersSnapshot()));
        r.add("response_headers", headerStats(info.respHeadersSnapshot()));
        r.add("cookies", headerStats(info.cookiesSnapshot()));
        r.add("technologies", toStrList(info.technologies(), 100));
        r.add("hosts", toStrList(info.hosts(), 200));
        r.add("emails", toStrList(info.emails(), 100));
        r.addProperty("note", "Aggregated across ALL in-scope requests. Secret values are masked; "
                + "fetch the full value from the specific request via get_request_response if needed.");
        return r;
    }

    private static JsonArray headerStats(java.util.List<InfoStore.NameStat> stats) {
        JsonArray a = new JsonArray();
        int n = 0;
        for (InfoStore.NameStat s : stats) {
            if (n++ >= 80) {
                break;
            }
            JsonObject o = new JsonObject();
            o.addProperty("name", s.name);
            o.addProperty("count", s.count.get());
            o.add("samples", toStrArray(s.samples));
            a.add(o);
        }
        return a;
    }

    private static JsonArray toStrList(java.util.List<String> list, int limit) {
        JsonArray a = new JsonArray();
        int n = 0;
        for (String s : list) {
            if (n++ >= limit) {
                break;
            }
            a.add(s);
        }
        return a;
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
        Audit audit = startAuditSafe(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS);
        if (audit == null) {
            return scannerUnavailable();
        }
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
        Audit audit = startAuditSafe(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
        if (audit == null) {
            return scannerUnavailable();
        }
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

    /** Start an audit, tolerating editions/versions without a Scanner (returns null on failure). */
    private Audit startAuditSafe(BuiltInAuditConfiguration cfg) {
        try {
            return api.scanner().startAudit(AuditConfiguration.auditConfiguration(cfg));
        } catch (Throwable t) {
            ctx.logError("Scanner audit unavailable: " + t);
            return null;
        }
    }

    private JsonObject scannerUnavailable() {
        JsonObject r = new JsonObject();
        r.addProperty("error", "Burp's Scanner isn't available in this edition (Burp Community has no "
                + "Scanner). Skip the audit and rely on passive analysis of captured traffic, "
                + "fetch_url / fetch_common_paths for recon, and send_http_request for targeted tests.");
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

    // ------------------------------------------------------------------ recon: fetch & extract

    /** Curated list of interesting recon / misconfiguration paths. */
    private static final String[] RECON_PATHS = {
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt",
            "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
            "/config.json", "/config.js", "/app.config.js", "/package.json", "/composer.json",
            "/yarn.lock", "/Dockerfile", "/docker-compose.yml", "/.DS_Store", "/.htaccess",
            "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml", "/server-status",
            "/server-info", "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
            "/metrics", "/phpinfo.php", "/info.php", "/swagger.json", "/swagger-ui.html",
            "/openapi.json", "/api-docs", "/v2/api-docs", "/graphql", "/graphiql",
            "/.svn/entries", "/wp-json/", "/wp-login.php", "/admin", "/administrator", "/login",
            "/backup.zip", "/backup.sql", "/dump.sql", "/.npmrc", "/elmah.axd", "/trace.axd",
            "/.well-known/openid-configuration",
            // source maps + CI/CD config (source/secret disclosure)
            "/main.js.map", "/app.js.map", "/bundle.js.map", "/index.js.map",
            "/.gitlab-ci.yml", "/.circleci/config.yml", "/Jenkinsfile", "/.travis.yml",
            "/.git-credentials", "/.aws/credentials", "/config/database.yml", "/appsettings.json",
    };

    private JsonObject extractFromCaptured(JsonObject args) {
        Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
        if (item == null || item.response == null) {
            return error("No captured response for that source/id.");
        }
        JsonObject r = ContentExtractor.extract(item.response.bodyToString(), item.url);
        r.addProperty("url", item.url);
        r.addProperty("status", item.response.statusCode());
        return r;
    }

    private JsonObject fetchUrl(JsonObject args) {
        String url = getStr(args, "url", null);
        if (url == null || url.isBlank()) {
            return error("url is required");
        }
        String method = getStr(args, "method", "GET");
        int maxBody = getInt(args, "max_body_bytes", 8000);
        HttpRequest req;
        try {
            req = HttpRequest.httpRequestFromUrl(url);
            if (!"GET".equalsIgnoreCase(method)) {
                req = req.withMethod(method.toUpperCase());
            }
        } catch (RuntimeException e) {
            return error("Could not build request for URL: " + e.getMessage());
        }
        HttpRequestResponse rr = api.http().sendRequest(req);
        JsonObject r = new JsonObject();
        r.addProperty("url", url);
        r.addProperty("method", req.method());
        if (rr.response() != null) {
            HttpResponse resp = rr.response();
            String body = resp.bodyToString();
            r.addProperty("status", resp.statusCode());
            r.addProperty("mime", resp.mimeType() == null ? "" : resp.mimeType().toString());
            r.addProperty("response_headers", headersToStringResp(resp));
            addTruncated(r, "response_body", body, maxBody);
            r.add("extracted", ContentExtractor.extract(body, url));
        } else {
            r.addProperty("status", 0);
            r.addProperty("note", "No response received.");
        }
        return r;
    }

    private JsonObject fetchCommonPaths(JsonObject args) {
        String base = getStr(args, "base_url", null);
        if (base == null || base.isBlank()) {
            return error("base_url is required (e.g. https://app.example.com)");
        }
        String[] paths = customPaths(args);
        int cap = Math.min(paths.length, 60);

        JsonArray results = new JsonArray();
        int found = 0;
        for (int i = 0; i < cap; i++) {
            String full = joinUrl(base, paths[i]);
            try {
                HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequestFromUrl(full));
                int status = rr.response() != null ? rr.response().statusCode() : 0;
                int len = rr.response() != null ? rr.response().body().length() : 0;
                String ct = rr.response() != null && rr.response().mimeType() != null
                        ? rr.response().mimeType().toString() : "";
                boolean interesting = (status == 200 || status == 201 || status == 401 || status == 403)
                        && len > 0;
                JsonObject o = new JsonObject();
                o.addProperty("path", paths[i]);
                o.addProperty("url", full);
                o.addProperty("status", status);
                o.addProperty("length", len);
                o.addProperty("content_type", ct);
                o.addProperty("interesting", interesting);
                results.add(o);
                if (interesting) {
                    found++;
                }
            } catch (RuntimeException e) {
                // skip unresolvable path
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("base_url", base);
        r.addProperty("tried", cap);
        r.addProperty("interesting_count", found);
        r.add("results", results);
        r.addProperty("note", "Review 'interesting' entries; fetch promising ones with fetch_url to "
                + "extract links/JS/endpoints/secrets.");
        return r;
    }

    /** Sensitive path fragments whose accessibility (or protected-ness) is a finding. */
    private static final String[] SENSITIVE_PATHS = {
            "admin", "config", "backup", "/.git", "/.env", "/.svn", "actuator", "debug", "swagger",
            "openapi", "graphql", "phpinfo", "console", "internal", "wp-admin", "server-status",
            "metrics", "/trace", "dump", "credential", "secret", "id_rsa", "/.ds_store", "/.htaccess",
            "/.aws", "/.npmrc", "database", "/db", "/logs", "/private", "/setup", "/install",
    };

    /**
     * Probe a set of paths on a base URL and classify each response. Pulls the paths the recon /
     * JS miner already DISCOVERED (so you probe the real attack surface, not just a static wordlist),
     * accepts an explicit list too, and can expand parent directories and common backup suffixes.
     * Safe methods only (GET/HEAD/OPTIONS); in-scope URLs only.
     */
    private JsonObject probePaths(JsonObject args) {
        String base = getStr(args, "base_url", null);
        if (base == null || base.isBlank()) {
            return error("base_url is required (e.g. https://app.example.com)");
        }
        String method = getStr(args, "method", "GET").toUpperCase();
        if (!method.equals("GET") && !method.equals("HEAD") && !method.equals("OPTIONS")) {
            return error("probe_paths only sends safe methods (GET/HEAD/OPTIONS). For verb testing use "
                    + "test_method_tampering.");
        }
        boolean useDiscovered = getBool(args, "use_discovered", true);
        boolean expandParents = getBool(args, "expand_parents", false);
        boolean checkBackups = getBool(args, "check_backups", false);
        int max = Math.min(getInt(args, "max", 80), 200);
        int delayMs = Math.max(0, getInt(args, "delay_ms", 0));
        String baseHost = hostOfUrl(base);

        // Collect candidate paths (ordered, deduped).
        java.util.LinkedHashSet<String> paths = new java.util.LinkedHashSet<>();
        if (args.has("paths") && args.get("paths").isJsonArray()) {
            for (JsonElement el : args.getAsJsonArray("paths")) {
                addPath(paths, el.getAsString());
            }
        }
        if (useDiscovered) {
            for (FindingsStore.EndpointInfo ep : findings.endpointsSnapshot()) {
                if (paths.size() > max * 2) {
                    break;
                }
                String epHost = hostOfUrl(ep.sampleUrl);
                if (baseHost != null && epHost != null && !baseHost.equalsIgnoreCase(epHost)) {
                    continue; // only paths for the host we're probing
                }
                addPath(paths, pathOfUrl(ep.sampleUrl));
            }
        }
        if (paths.isEmpty()) {
            return error("No paths to probe. Provide 'paths', or run recon / mine_javascript first so "
                    + "endpoints are discovered (then keep use_discovered=true).");
        }
        if (expandParents) {
            for (String p : new ArrayList<>(paths)) {
                for (String parent : parentDirs(p)) {
                    addPath(paths, parent);
                }
            }
        }
        if (checkBackups) {
            for (String p : new ArrayList<>(paths)) {
                if (p.contains(".") && !p.endsWith("/")) {
                    for (String suf : new String[]{".bak", ".old", "~", ".orig", ".save", ".zip"}) {
                        addPath(paths, p + suf);
                    }
                }
            }
        }

        JsonArray results = new JsonArray();
        JsonArray interesting = new JsonArray();
        Map<String, Integer> byClass = new LinkedHashMap<>();
        int probed = 0;
        int skippedScope = 0;
        int recorded = 0;
        for (String path : paths) {
            if (probed >= max) {
                break;
            }
            String full = joinUrl(base, path);
            if (!isInScope(full)) {
                skippedScope++;
                continue;
            }
            try {
                HttpRequestResponse rr = api.http().sendRequest(
                        HttpRequest.httpRequestFromUrl(full).withMethod(method));
                HttpResponse resp = rr.response();
                int status = resp != null ? resp.statusCode() : 0;
                int len = resp != null ? resp.body().length() : 0;
                String ct = resp != null && resp.mimeType() != null ? resp.mimeType().toString() : "";
                String loc = resp != null ? resp.headerValue("Location") : null;
                probed++;
                byClass.merge(statusClass(status), 1, Integer::sum);

                JsonObject o = new JsonObject();
                o.addProperty("path", path);
                o.addProperty("url", full);
                o.addProperty("status", status);
                o.addProperty("length", len);
                o.addProperty("content_type", ct);
                if (loc != null) {
                    o.addProperty("location", loc);
                }
                String verdict = probeVerdict(status);
                o.addProperty("verdict", verdict);
                boolean sensitive = isSensitivePath(path);
                boolean note = !"not found".equals(verdict) && !"error/none".equals(verdict);
                if (note) {
                    results.add(o);
                }
                if (note && (sensitive || status == 200 || status == 401 || status == 403 || status == 500)) {
                    interesting.add(o);
                }
                // Auto-record sensitive exposure / protected sensitive endpoints.
                if (sensitive && (status == 200 || status == 201)) {
                    if (findings.addFinding(new PassiveFinding("Sensitive path accessible", "Medium",
                            "Firm", full, method + " " + status + " (" + len + "b) — sensitive path reachable.",
                            true))) {
                        recorded++;
                    }
                } else if (sensitive && (status == 401 || status == 403)) {
                    if (findings.addFinding(new PassiveFinding("Sensitive path present (protected)", "Info",
                            "Firm", full, method + " " + status + " — exists but access-controlled; "
                            + "candidate for authz/verb bypass.", true))) {
                        recorded++;
                    }
                }
            } catch (RuntimeException e) {
                // skip unresolvable/failed path
            }
            if (delayMs > 0) {
                sleepQuietly(delayMs);
            }
        }
        JsonObject dist = new JsonObject();
        byClass.forEach(dist::addProperty);

        JsonObject r = new JsonObject();
        r.addProperty("base_url", base);
        r.addProperty("candidates", paths.size());
        r.addProperty("probed", probed);
        r.addProperty("skipped_out_of_scope", skippedScope);
        r.addProperty("findings_recorded", recorded);
        r.add("status_distribution", dist);
        r.add("interesting", interesting);
        r.add("results", results);
        r.addProperty("note", "200 = accessible; 401/403 = exists but protected (authz/verb-bypass "
                + "candidate — try authz_matrix / test_method_tampering); 405 = method not allowed; "
                + "5xx = server error. fetch_url a promising hit to mine it further.");
        return r;
    }

    private static void addPath(java.util.LinkedHashSet<String> set, String raw) {
        if (raw == null) {
            return;
        }
        String p = raw.trim();
        if (p.isEmpty()) {
            return;
        }
        // Accept absolute URLs by reducing to their path.
        if (p.startsWith("http://") || p.startsWith("https://")) {
            p = pathOfUrl(p);
        }
        if (p == null || p.isEmpty()) {
            return;
        }
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        set.add(p);
    }

    private static List<String> parentDirs(String path) {
        List<String> out = new ArrayList<>();
        String p = path;
        int guard = 0;
        while (p.length() > 1 && guard++ < 8) {
            int slash = p.lastIndexOf('/', p.endsWith("/") ? p.length() - 2 : p.length() - 1);
            if (slash <= 0) {
                break;
            }
            String parent = p.substring(0, slash + 1); // keep trailing slash
            out.add(parent);
            p = p.substring(0, slash);
        }
        return out;
    }

    private static boolean isSensitivePath(String path) {
        String lc = path.toLowerCase();
        for (String s : SENSITIVE_PATHS) {
            if (lc.contains(s)) {
                return true;
            }
        }
        return false;
    }

    private static String statusClass(int status) {
        if (status >= 200 && status < 300) {
            return "2xx";
        }
        if (status >= 300 && status < 400) {
            return "3xx";
        }
        if (status >= 400 && status < 500) {
            return "4xx";
        }
        if (status >= 500) {
            return "5xx";
        }
        return "none";
    }

    private static String probeVerdict(int status) {
        if (status >= 200 && status < 300) {
            return "accessible";
        }
        if (status == 401 || status == 403) {
            return "protected (exists)";
        }
        if (status == 405) {
            return "method not allowed";
        }
        if (status >= 300 && status < 400) {
            return "redirect";
        }
        if (status == 404 || status == 410) {
            return "not found";
        }
        if (status >= 500) {
            return "server error";
        }
        return "error/none";
    }

    private static String hostOfUrl(String url) {
        try {
            return java.net.URI.create(url).getHost();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** scheme://host[:port] of a URL, or null. */
    private static String originOf(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            if (u.getScheme() == null || u.getHost() == null) {
                return null;
            }
            String port = u.getPort() > 0 ? ":" + u.getPort() : "";
            return u.getScheme() + "://" + u.getHost() + port;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Resolve a mined endpoint (absolute or path-only) to an absolute URL against {@code origin}. */
    private static String toAbsoluteUrl(String origin, String endpoint) {
        if (endpoint == null || endpoint.isBlank()) {
            return null;
        }
        String e = endpoint.trim();
        if (e.startsWith("http://") || e.startsWith("https://")) {
            return e;
        }
        if (origin == null || !e.startsWith("/")) {
            return null; // skip relative/ambiguous fragments we can't anchor
        }
        return origin + e;
    }

    private static String pathOfUrl(String url) {
        try {
            java.net.URI u = java.net.URI.create(url);
            String path = u.getRawPath();
            return path == null || path.isEmpty() ? "/" : path;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String[] customPaths(JsonObject args) {
        if (args.has("paths") && args.get("paths").isJsonArray()) {
            JsonArray a = args.getAsJsonArray("paths");
            if (a.size() > 0) {
                String[] out = new String[a.size()];
                for (int i = 0; i < a.size(); i++) {
                    out[i] = a.get(i).getAsString();
                }
                return out;
            }
        }
        return RECON_PATHS;
    }

    private static String joinUrl(String base, String path) {
        String b = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        String p = path.startsWith("/") ? path : "/" + path;
        return b + p;
    }

    // ------------------------------------------------------------------ OAST (out-of-band)

    private JsonObject createOastPayload(JsonObject args) {
        String label = getStr(args, "label", null);
        try {
            CollaboratorPayload p = oast.generate(label);
            JsonObject r = new JsonObject();
            r.addProperty("payload_domain", p.toString());
            r.addProperty("payload_url", "http://" + p);
            r.addProperty("interaction_id", p.id().toString());
            if (label != null) {
                r.addProperty("label", label);
            }
            r.addProperty("note", "Inject this domain/URL into a candidate BLIND sink (SSRF/XXE/blind "
                    + "XSS/SQLi/RCE) — e.g. via test_injection oracle=oob, or send_http_request. Then "
                    + "call poll_oast_interactions to see DNS/HTTP callbacks.");
            return r;
        } catch (Throwable t) {
            return error("Collaborator/OAST is unavailable (disabled or blocked): " + t.getMessage());
        }
    }

    private JsonObject pollOastInteractions(JsonObject args) {
        String label = getStr(args, "label", null);
        try {
            List<Interaction> list = oast.poll();
            JsonArray arr = new JsonArray();
            for (Interaction i : list) {
                String cd = i.customData().orElse("");
                if (label != null && !label.isBlank() && !label.equals(cd)) {
                    continue;
                }
                JsonObject o = new JsonObject();
                o.addProperty("type", i.type().name());
                o.addProperty("time", i.timeStamp() == null ? "" : i.timeStamp().toString());
                try {
                    o.addProperty("client_ip", i.clientIp() == null ? "" : i.clientIp().getHostAddress());
                } catch (RuntimeException ignored) {
                    // no client ip
                }
                if (!cd.isEmpty()) {
                    o.addProperty("label", cd);
                }
                arr.add(o);
            }
            JsonObject r = new JsonObject();
            r.add("interactions", arr);
            r.addProperty("count", arr.size());
            if (arr.size() == 0) {
                r.addProperty("note", "No callbacks yet. Blind bugs can take seconds to minutes — poll "
                        + "again after injecting the payload.");
            }
            return r;
        } catch (Throwable t) {
            return error("OAST poll failed: " + t.getMessage());
        }
    }

    // ------------------------------------------------------------------ identities / access control

    private JsonObject setIdentity(JsonObject args) {
        String name = getStr(args, "name", null);
        if (name == null || name.isBlank()) {
            return error("name is required");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        if (args.has("headers") && args.get("headers").isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : args.getAsJsonObject("headers").entrySet()) {
                if (e.getValue().isJsonPrimitive()) {
                    headers.put(e.getKey(), e.getValue().getAsString());
                }
            }
        }
        if (headers.isEmpty()) {
            return error("Provide at least one auth header in 'headers' (e.g. Cookie, Authorization, apikey).");
        }
        identities.set(name, headers);
        JsonObject r = new JsonObject();
        r.addProperty("stored", true);
        r.addProperty("name", name);
        r.addProperty("header_count", headers.size());
        return r;
    }

    private JsonObject listIdentities() {
        JsonArray arr = new JsonArray();
        for (String n : identities.names()) {
            arr.add(n);
        }
        JsonObject r = new JsonObject();
        r.add("identities", arr);
        r.addProperty("note", "Use these with authz_matrix. The special identity '"
                + IdentityStore.UNAUTH + "' strips all auth headers.");
        return r;
    }

    private JsonObject authzMatrix(JsonObject args) {
        HttpRequest base;
        try {
            base = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        // Reference = the request as captured (the authorized user's own identity).
        HttpRequestResponse ref = api.http().sendRequest(base);
        int refStatus = statusOf(ref);
        String refBody = bodyStr(ref);

        List<String> names = new ArrayList<>();
        if (args.has("identities") && args.get("identities").isJsonArray()) {
            for (JsonElement e : args.getAsJsonArray("identities")) {
                names.add(e.getAsString());
            }
        } else {
            names.addAll(identities.names());
            names.add(IdentityStore.UNAUTH);
        }

        JsonArray rows = new JsonArray();
        for (String name : names) {
            if (!identities.has(name)) {
                continue;
            }
            HttpRequest r2 = identities.apply(base, name);
            HttpRequestResponse rr = api.http().sendRequest(r2);
            int st = statusOf(rr);
            double sim = ResponseDiff.similarity(refBody, bodyStr(rr));
            boolean flag = (st == 200 || st == 201) && sim >= 0.9;
            JsonObject row = new JsonObject();
            row.addProperty("identity", name);
            row.addProperty("status", st);
            row.addProperty("similarity_to_authorized", Math.round(sim * 1000) / 1000.0);
            row.addProperty("possible_broken_access_control", flag);
            rows.add(row);
        }
        JsonObject r = new JsonObject();
        r.addProperty("authorized_status", refStatus);
        r.addProperty("url", base.url());
        r.add("matrix", rows);
        r.addProperty("note", "A lower-privilege / unauthenticated identity returning a 200 that closely "
                + "matches the authorized response is a likely IDOR/BOLA/broken-access-control. Verify "
                + "the data actually belongs to another user.");
        return r;
    }

    // ------------------------------------------------------------------ oracle-based injection

    private JsonObject testInjection(JsonObject args) {
        String cls = getStr(args, "inject_class", "").toLowerCase();
        String param = getStr(args, "param_name", null);
        String type = getStr(args, "param_type", "url");
        if (param == null && !"oob".equals(cls)) {
            return error("param_name is required");
        }
        HttpRequest base;
        try {
            base = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        switch (cls) {
            case "ssti":
                return oracleSsti(base, param, type);
            case "sqli_error":
                return oracleError(base, param, type, "SQL injection (error-based)", "High",
                        Payloads.SQLI_ERROR, Payloads.SQL_ERROR_SIGNS);
            case "path_traversal":
                return oracleError(base, param, type, "Path traversal", "High",
                        Payloads.PATH_TRAVERSAL, Payloads.TRAVERSAL_SIGNS);
            case "sqli_time":
                return oracleTime(base, param, type, "SQL injection (time-based)", Payloads.SQLI_TIME);
            case "cmdi_time":
                return oracleTime(base, param, type, "Command injection (time-based)", Payloads.CMDI_TIME);
            case "sqli_boolean":
                return oracleBoolean(base, param, type);
            case "oob":
                return oracleOob(base, param, type, getStr(args, "oast_domain", null));
            default:
                return error("Unknown inject_class. Use: ssti, sqli_error, sqli_time, sqli_boolean, "
                        + "cmdi_time, path_traversal, oob.");
        }
    }

    private JsonObject oracleSsti(HttpRequest base, String param, String type) {
        for (String p : Payloads.SSTI) {
            HttpRequest r = injectParam(base, param, type, p);
            String body = bodyStr(api.http().sendRequest(r));
            if (body.contains("49") && !body.contains(p)) {
                return vulnFinding("SSTI (server-side template injection)", "High", "Firm",
                        r.url(), param, "math", "Payload " + p + " evaluated to 49 in the response.", p);
            }
        }
        return notVuln("SSTI", param);
    }

    private JsonObject oracleError(HttpRequest base, String param, String type, String cls, String sev,
                                   String[] payloads, String[] signs) {
        for (String p : payloads) {
            HttpRequest r = injectParam(base, param, type, p);
            String body = bodyStr(api.http().sendRequest(r));
            for (String sign : signs) {
                if (body.contains(sign)) {
                    return vulnFinding(cls, sev, "Firm", r.url(), param, "error/echo",
                            "Payload " + p + " triggered: " + sign, p);
                }
            }
        }
        return notVuln(cls, param);
    }

    private JsonObject oracleTime(HttpRequest base, String param, String type, String cls, String[] payloads) {
        long baseline = sendTimedMs(injectParam(base, param, type, "az123"));
        long bestDelta = 0;
        for (String p : payloads) {
            long ms = sendTimedMs(injectParam(base, param, type, p));
            long delta = ms - baseline;
            bestDelta = Math.max(bestDelta, delta);
            if (delta > 4000) {
                JsonObject o = vulnFinding(cls, "High", "Firm", base.url(), param, "time",
                        "Payload " + p + " delayed the response by ~" + delta + "ms (baseline "
                        + baseline + "ms).", p);
                o.addProperty("baseline_ms", baseline);
                o.addProperty("delayed_ms", ms);
                return o;
            }
        }
        JsonObject o = notVuln(cls, param);
        o.addProperty("baseline_ms", baseline);
        o.addProperty("max_delta_ms", bestDelta);
        return o;
    }

    private JsonObject oracleBoolean(HttpRequest base, String param, String type) {
        String refBody = bodyStr(api.http().sendRequest(injectParam(base, param, type, "az123")));
        int n = Math.min(Payloads.SQLI_BOOL_TRUE.length, Payloads.SQLI_BOOL_FALSE.length);
        for (int i = 0; i < n; i++) {
            String tBody = bodyStr(api.http().sendRequest(injectParam(base, param, type, Payloads.SQLI_BOOL_TRUE[i])));
            String fBody = bodyStr(api.http().sendRequest(injectParam(base, param, type, Payloads.SQLI_BOOL_FALSE[i])));
            double simTrue = ResponseDiff.similarity(refBody, tBody);
            double simFalse = ResponseDiff.similarity(refBody, fBody);
            if (simTrue >= 0.9 && simFalse < 0.7) {
                return vulnFinding("SQL injection (boolean-based)", "Medium", "Tentative", base.url(),
                        param, "boolean", "TRUE condition ~= baseline (sim " + round(simTrue)
                        + ") while FALSE differs (sim " + round(simFalse) + ").",
                        Payloads.SQLI_BOOL_TRUE[i]);
            }
        }
        return notVuln("SQL injection (boolean-based)", param);
    }

    private JsonObject oracleOob(HttpRequest base, String param, String type, String domain) {
        if (domain == null || domain.isBlank()) {
            return error("oast_domain is required for the oob oracle — call create_oast_payload first.");
        }
        HttpRequest r = injectParam(base, param == null ? "url" : param, type, "http://" + domain + "/");
        api.http().sendRequest(r);
        JsonObject o = new JsonObject();
        o.addProperty("class", "oob (blind SSRF/XXE/RCE)");
        o.addProperty("injected", true);
        o.addProperty("url", r.url());
        o.addProperty("note", "Injected the OAST URL. Call poll_oast_interactions to check for a callback; "
                + "a DNS/HTTP hit confirms the blind vulnerability.");
        return o;
    }

    // ------------------------------------------------------------------ param discovery & race

    private static final String[] DEFAULT_PARAMS = {
            "id", "user", "user_id", "uid", "account", "admin", "debug", "test", "role", "page",
            "redirect", "url", "next", "return", "returnUrl", "callback", "file", "path", "dir",
            "search", "q", "query", "lang", "format", "view", "action", "cmd", "exec", "include",
            "template", "name", "email", "token", "key", "order", "sort", "limit", "offset", "filter",
            "type", "mode", "status", "enable", "preview", "draft", "json", "xml", "download",
    };

    private JsonObject discoverParams(JsonObject args) {
        HttpRequest base;
        try {
            base = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        String[] words = customList(args, "wordlist", DEFAULT_PARAMS);
        HttpRequestResponse baseRR = api.http().sendRequest(base);
        int baseStatus = statusOf(baseRR);
        String baseBody = bodyStr(baseRR);

        JsonArray hits = new JsonArray();
        int tried = 0;
        for (String w : words) {
            if (tried >= 60) {
                break;
            }
            tried++;
            String canary = "zqx" + tried + "cn";
            HttpRequest r = injectParam(base, w, "url", canary);
            HttpRequestResponse rr = api.http().sendRequest(r);
            String body = bodyStr(rr);
            boolean reflected = body.contains(canary);
            JsonObject cmp = ResponseDiff.compare(baseStatus, baseBody, statusOf(rr), body);
            boolean changed = cmp.get("significantly_different").getAsBoolean();
            if (reflected || changed) {
                JsonObject o = new JsonObject();
                o.addProperty("param", w);
                o.addProperty("reflected", reflected);
                o.addProperty("status", statusOf(rr));
                o.addProperty("changed_response", changed);
                hits.add(o);
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("tried", tried);
        r.addProperty("candidates_found", hits.size());
        r.add("params", hits);
        r.addProperty("note", "Reflected or response-changing params are worth testing for injection/IDOR.");
        return r;
    }

    private JsonObject raceRequests(JsonObject args) {
        HttpRequest req;
        try {
            req = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        int count = Math.min(getInt(args, "count", 20), 30);
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(count, 20));
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < count; i++) {
                futures.add(pool.submit(() -> statusOf(api.http().sendRequest(req))));
            }
            Map<String, Integer> dist = new LinkedHashMap<>();
            for (Future<Integer> f : futures) {
                int st;
                try {
                    st = f.get(30, TimeUnit.SECONDS);
                } catch (Exception e) {
                    st = 0;
                }
                dist.merge(String.valueOf(st), 1, Integer::sum);
            }
            JsonObject distObj = new JsonObject();
            dist.forEach(distObj::addProperty);
            JsonObject r = new JsonObject();
            r.addProperty("sent", count);
            r.addProperty("url", req.url());
            r.add("status_distribution", distObj);
            r.addProperty("note", "Look for a minority status/behaviour that differs from the pack — a "
                    + "limit-bypass / double-spend / TOCTOU race signal.");
            return r;
        } finally {
            pool.shutdownNow();
        }
    }

    // ------------------------------------------------------------------ API-specific testing

    /**
     * Send a GraphQL introspection query and report whether the schema comes back (introspection
     * left enabled in production is an info-leak that maps the whole API attack surface).
     */
    private JsonObject graphqlIntrospect(JsonObject args) {
        HttpRequest base;
        try {
            base = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage() + " (or pass a raw_request/base pointing at the GraphQL endpoint).");
        }
        HttpRequest req = base.withMethod("POST")
                .withUpdatedHeader("Content-Type", "application/json")
                .withBody(Payloads.GRAPHQL_INTROSPECTION);
        HttpRequestResponse rr = api.http().sendRequest(req);
        String body = bodyStr(rr);

        boolean enabled = body.contains("__schema") && body.contains("\"types\"");
        boolean looksGraphql = false;
        for (String s : Payloads.GRAPHQL_SIGNS) {
            if (body.contains(s)) {
                looksGraphql = true;
                break;
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("url", req.url());
        r.addProperty("status", statusOf(rr));
        r.addProperty("looks_like_graphql", looksGraphql);
        r.addProperty("introspection_enabled", enabled);
        if (enabled) {
            r.addProperty("type_count", countOccurrences(body, "\"name\""));
            r.addProperty("has_mutations", body.contains("mutationType") && !body.contains("\"mutationType\":null"));
            addTruncated(r, "schema_excerpt", body, 4000);
            r.addProperty("note", "Introspection is ENABLED — the full schema (types, queries, mutations) is "
                    + "exposed. Record with report_finding, then mine the schema for sensitive "
                    + "queries/mutations and object-level access-control (BOLA) targets.");
        } else if (looksGraphql) {
            r.addProperty("note", "GraphQL endpoint detected but introspection appears disabled. Try field "
                    + "suggestion ('Did you mean') to infer the schema, and test known operations for "
                    + "authorization flaws and batching/alias-based rate-limit bypass.");
        } else {
            r.addProperty("note", "Response doesn't look like GraphQL — confirm the endpoint path (often "
                    + "/graphql, /api/graphql, /query).");
        }
        return r;
    }

    /**
     * Replay the request with a range of HTTP verbs (and method-override headers) and report which
     * are accepted — a verb the app didn't expect can bypass access control or hit an unintended
     * write handler. Authorized-only because PUT/PATCH/DELETE can change state.
     */
    private JsonObject testMethodTampering(JsonObject args) {
        HttpRequest base;
        try {
            base = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        HttpRequestResponse baseRR = api.http().sendRequest(base);
        int baseStatus = statusOf(baseRR);
        String origMethod = base.method();

        JsonArray results = new JsonArray();
        JsonArray interesting = new JsonArray();
        for (String method : Payloads.TAMPER_METHODS) {
            if (method.equalsIgnoreCase(origMethod)) {
                continue;
            }
            int status;
            try {
                status = statusOf(api.http().sendRequest(base.withMethod(method)));
            } catch (RuntimeException e) {
                continue;
            }
            JsonObject o = new JsonObject();
            o.addProperty("method", method);
            o.addProperty("status", status);
            results.add(o);
            // 2xx/3xx on a non-standard or state-changing verb is worth a closer look.
            boolean accepted = status >= 200 && status < 400;
            boolean risky = method.equals("PUT") || method.equals("DELETE") || method.equals("PATCH")
                    || method.equals("TRACE") || method.equals("PROPFIND") || method.equals("FOO");
            if (accepted && risky) {
                interesting.add(o);
            }
        }
        // Method-override headers: keep the original verb but ask the app to treat it as PUT/DELETE.
        JsonArray overrides = new JsonArray();
        for (String h : Payloads.METHOD_OVERRIDE_HEADERS) {
            for (String v : new String[]{"PUT", "DELETE"}) {
                int status = statusOf(api.http().sendRequest(base.withMethod("POST").withUpdatedHeader(h, v)));
                if (status != baseStatus && status >= 200 && status < 400) {
                    JsonObject o = new JsonObject();
                    o.addProperty("header", h);
                    o.addProperty("value", v);
                    o.addProperty("status", status);
                    overrides.add(o);
                }
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("url", base.url());
        r.addProperty("original_method", origMethod);
        r.addProperty("baseline_status", baseStatus);
        r.add("method_results", results);
        r.add("accepted_risky_methods", interesting);
        r.add("accepted_override_headers", overrides);
        r.addProperty("note", (interesting.size() > 0 || overrides.size() > 0)
                ? "A state-changing verb / override was accepted. Verify it actually performs the action "
                  + "(not a generic 200) before recording — this can be an access-control or CSRF bypass."
                : "No unexpected verb accepted.");
        return r;
    }

    /**
     * Over-post privileged fields onto a write request (JSON body or form params) and diff the
     * response — a privilege value that appears/echoes in the result is a mass-assignment signal.
     * Authorized-only: this mutates the target object.
     */
    private JsonObject testMassAssignment(JsonObject args) {
        HttpRequest base;
        try {
            base = buildRequestFromSpec(args);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        HttpRequestResponse baseRR = api.http().sendRequest(base);
        int baseStatus = statusOf(baseRR);
        String baseBody = bodyStr(baseRR);
        String ct = headerValue(base, "Content-Type");
        boolean json = ct != null && ct.toLowerCase().contains("json");

        JsonArray hits = new JsonArray();
        int tried = 0;
        for (String[] field : Payloads.MASS_ASSIGN_FIELDS) {
            String name = field[0];
            String value = field[1];
            HttpRequest r = json ? injectJsonField(base, name, value)
                    : base.withParameter(HttpParameter.parameter(name, value, HttpParameterType.BODY));
            tried++;
            HttpRequestResponse rr = api.http().sendRequest(r);
            String body = bodyStr(rr);
            int status = statusOf(rr);
            // Signal: the injected field/value is echoed back, or the write now succeeds where the
            // baseline didn't, or the response body meaningfully changes.
            boolean echoed = body.contains("\"" + name + "\"") && body.contains(value);
            JsonObject cmp = ResponseDiff.compare(baseStatus, baseBody, status, body);
            boolean changed = cmp.get("significantly_different").getAsBoolean();
            if (echoed || (changed && status >= 200 && status < 300)) {
                JsonObject o = new JsonObject();
                o.addProperty("field", name);
                o.addProperty("value", value);
                o.addProperty("status", status);
                o.addProperty("echoed_in_response", echoed);
                o.addProperty("changed_response", changed);
                hits.add(o);
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("url", base.url());
        r.addProperty("body_style", json ? "json" : "form");
        r.addProperty("fields_tried", tried);
        r.add("candidates", hits);
        r.addProperty("note", hits.size() > 0
                ? "Privileged field(s) were accepted/echoed — verify the privilege actually persisted "
                  + "(re-fetch the object as the same or a lower-priv identity) before recording."
                : "No mass-assignment signal from the tried fields.");
        return r;
    }

    /** Inject/replace a top-level field in a JSON body (string-level, tolerant of non-strict JSON). */
    private HttpRequest injectJsonField(HttpRequest req, String name, String value) {
        String body = req.bodyToString();
        String field = "\"" + name + "\":\"" + value + "\"";
        String trimmed = body == null ? "" : body.trim();
        String newBody;
        if (trimmed.startsWith("{") && trimmed.length() >= 2) {
            int close = trimmed.lastIndexOf('}');
            String inner = trimmed.substring(1, close).trim();
            newBody = inner.isEmpty() ? "{" + field + "}" : "{" + inner + "," + field + "}";
        } else {
            newBody = "{" + field + "}";
        }
        return req.withBody(newBody);
    }

    private static String headerValue(HttpRequest req, String name) {
        return req.hasHeader(name) ? req.headerValue(name) : null;
    }

    /** QoL: render a captured (or modified) request as a copy-pasteable curl command. Read-only. */
    private JsonObject toCurl(JsonObject args) {
        HttpRequest req;
        try {
            // Support both {source,id} and the {base_id,base_source,raw_request,modifications} spec.
            if (getStr(args, "base_id", null) == null && getStr(args, "raw_request", null) == null
                    && getStr(args, "id", null) != null) {
                Item it = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
                if (it == null) {
                    return error("No captured item for that source/id.");
                }
                req = applyMutations(it.request,
                        args.has("modifications") ? args.getAsJsonArray("modifications") : null);
            } else {
                req = buildRequestFromSpec(args);
            }
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }
        boolean includeBody = getBool(args, "include_body", true);
        StringBuilder sb = new StringBuilder("curl -i -sS -X ").append(req.method())
                .append(" '").append(shellQuote(req.url())).append('\'');
        for (HttpHeader h : req.headers()) {
            String n = h.name();
            if (n == null || n.startsWith(":") || n.equalsIgnoreCase("Content-Length")) {
                continue;
            }
            sb.append(" \\\n  -H '").append(shellQuote(n + ": " + h.value())).append('\'');
        }
        String body = req.bodyToString();
        if (includeBody && body != null && !body.isEmpty()) {
            sb.append(" \\\n  --data-raw '").append(shellQuote(body)).append('\'');
        }
        JsonObject r = new JsonObject();
        r.addProperty("url", req.url());
        r.addProperty("method", req.method());
        r.addProperty("curl", sb.toString());
        r.addProperty("note", "Copy-paste to reproduce the request in a terminal. Uses -i to show "
                + "response headers; drop it for body-only.");
        return r;
    }

    /** Escape a value for single-quoted shell context: ' -> '\'' . */
    private static String shellQuote(String s) {
        return s == null ? "" : s.replace("'", "'\\''");
    }

    // ------------------------------------------------------------------ JavaScript miner

    /**
     * Deep-mine JavaScript already captured in Burp. With a source+id it mines that one item;
     * otherwise it sweeps every JavaScript response in the Proxy history (optionally filtered by
     * host). Read-only: it sends no traffic. High-value secrets are auto-recorded as findings; the
     * result hands the agent a prioritized list of vuln leads (endpoints, sinks, insecure patterns)
     * to test with the active tools.
     */
    private JsonObject mineJavascript(JsonObject args) {
        String source = getStr(args, "source", null);
        String id = getStr(args, "id", null);
        String hostContains = getStr(args, "host_contains", null);
        int maxFiles = Math.min(getInt(args, "max_files", 15), 40);

        List<Item> targets = new ArrayList<>();
        if (id != null) {
            Item it = resolve(source == null ? "proxy" : source, id);
            if (it == null) {
                return error("No captured item for that source/id.");
            }
            targets.add(it);
        } else {
            // Sweep the proxy history for JavaScript responses.
            for (ProxyHttpRequestResponse h : api.proxy().history()) {
                if (targets.size() >= maxFiles) {
                    break;
                }
                if (h.request() == null || h.response() == null) {
                    continue;
                }
                String url = safeUrl(h);
                if (hostContains != null && !url.toLowerCase().contains(hostContains.toLowerCase())) {
                    continue;
                }
                if (!looksLikeJs(url, h.response())) {
                    continue;
                }
                targets.add(item(h.request(), h.response(), url));
            }
        }
        if (targets.isEmpty()) {
            return error("No JavaScript found to mine. Browse the target so JS loads through the proxy, "
                    + "or fetch a specific .js with fetch_url first, then mine it by id.");
        }

        JsonArray files = new JsonArray();
        JsonArray allLeads = new JsonArray();
        int totalSecrets = 0;
        int totalEndpoints = 0;
        int recorded = 0;
        for (Item it : targets) {
            String body = it.response != null ? it.response.bodyToString() : "";
            JsonObject mined = JsMiner.mine(body, it.url);

            JsonObject fileSummary = new JsonObject();
            fileSummary.addProperty("url", it.url);
            fileSummary.add("summary", mined.getAsJsonObject("summary"));
            // Keep the per-file payload compact; the full detail lives under the richest categories.
            for (String k : new String[]{"secrets", "vuln_leads", "endpoints", "api_calls",
                    "debug_feature_flags", "insecure_patterns", "interesting_comments"}) {
                if (mined.has(k) && mined.get(k).isJsonArray() && mined.getAsJsonArray(k).size() > 0) {
                    fileSummary.add(k, mined.get(k));
                }
            }
            files.add(fileSummary);

            if (mined.has("summary")) {
                JsonObject s = mined.getAsJsonObject("summary");
                totalSecrets += s.get("secrets").getAsInt();
                totalEndpoints += s.get("endpoints").getAsInt();
            }
            // QoL: register discovered endpoints so they show in the Recon tab and can be probe_paths'd.
            String origin = originOf(it.url);
            for (String key : new String[]{"endpoints", "api_calls"}) {
                if (mined.has(key)) {
                    for (JsonElement e : mined.getAsJsonArray(key)) {
                        String abs = toAbsoluteUrl(origin, e.getAsString());
                        if (abs != null) {
                            findings.recordEndpoint(null, abs, 0);
                        }
                    }
                }
            }
            // Auto-record High-severity leads (exposed secrets, TLS/CSRF disabled, hard-coded creds).
            for (JsonElement le : mined.getAsJsonArray("vuln_leads")) {
                JsonObject lead = le.getAsJsonObject();
                allLeads.add(lead);
                if ("High".equals(lead.get("severity").getAsString())) {
                    boolean isNew = findings.addFinding(new PassiveFinding(
                            "JS: " + lead.get("type").getAsString(), "High", "Tentative", it.url,
                            lead.get("evidence").getAsString(), true));
                    if (isNew) {
                        recorded++;
                    }
                }
            }
        }

        JsonObject r = new JsonObject();
        r.addProperty("files_mined", targets.size());
        r.addProperty("total_secrets", totalSecrets);
        r.addProperty("total_endpoints", totalEndpoints);
        r.addProperty("high_severity_recorded", recorded);
        r.add("files", files);
        r.addProperty("note", "Static JS analysis. Verify each secret is live before reporting; feed the "
                + "discovered endpoints/api_calls into the active tools (auth/IDOR via authz_matrix, "
                + "injection via test_injection); if a source map is referenced, fetch it to recover "
                + "original source. High-severity leads were added to the AI Recon findings.");
        return r;
    }

    /** Heuristic: is this captured item JavaScript worth mining? */
    private static boolean looksLikeJs(String url, HttpResponse resp) {
        String lc = url == null ? "" : url.toLowerCase();
        int q = lc.indexOf('?');
        String path = q > 0 ? lc.substring(0, q) : lc;
        if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".jsx")
                || path.endsWith(".ts") || path.endsWith(".map")) {
            return true;
        }
        if (resp == null) {
            return false;
        }
        String ct = resp.headerValue("Content-Type");
        if (ct == null) {
            String mime = resp.mimeType() == null ? "" : resp.mimeType().toString().toLowerCase();
            return mime.contains("script");
        }
        String c = ct.toLowerCase();
        return c.contains("javascript") || c.contains("ecmascript");
    }

    // ------------------------------------------------------------------ client-side analysis & findings

    private JsonObject analyzeClientSide(JsonObject args) {
        Item item = resolve(getStr(args, "source", "proxy"), getStr(args, "id", null));
        if (item == null || item.response == null) {
            return error("No captured response for that source/id.");
        }
        String body = item.response.bodyToString();
        String scan = body.length() > 400_000 ? body.substring(0, 400_000) : body;

        JsonArray sinks = new JsonArray();
        for (String s : Payloads.JS_SINKS) {
            int idx = scan.indexOf(s);
            if (idx >= 0) {
                JsonObject o = new JsonObject();
                o.addProperty("sink", s);
                o.addProperty("snippet", snippetAt(scan, idx));
                sinks.add(o);
            }
        }
        JsonObject r = new JsonObject();
        r.addProperty("url", item.url);
        r.add("dangerous_sinks", sinks);
        r.addProperty("postmessage_handlers",
                countOccurrences(scan, "addEventListener(\"message\"")
                        + countOccurrences(scan, "addEventListener('message'")
                        + countOccurrences(scan, "onmessage"));
        JsonArray proto = new JsonArray();
        for (String pat : new String[]{"__proto__", "constructor.prototype", "prototype["}) {
            if (scan.contains(pat)) {
                proto.add(pat);
            }
        }
        r.add("prototype_pollution_hints", proto);

        // CSP (from the response header) — flag weaknesses.
        String csp = item.response.headerValue("Content-Security-Policy");
        JsonObject cspObj = new JsonObject();
        cspObj.addProperty("present", csp != null);
        if (csp != null) {
            JsonArray weak = new JsonArray();
            String lc = csp.toLowerCase();
            if (lc.contains("unsafe-inline")) {
                weak.add("'unsafe-inline' allows inline scripts (XSS-friendly)");
            }
            if (lc.contains("unsafe-eval")) {
                weak.add("'unsafe-eval' allows eval()");
            }
            if (lc.contains("*")) {
                weak.add("wildcard source present");
            }
            if (!lc.contains("object-src")) {
                weak.add("no object-src (plugin/XSS vector)");
            }
            cspObj.add("weaknesses", weak);
        }
        r.add("csp", cspObj);
        r.addProperty("note", "Sinks fed from user-controlled sources (location/hash/postMessage/name) "
                + "are DOM-XSS candidates; verify the source→sink data flow.");
        return r;
    }

    private JsonObject reportFinding(JsonObject args) {
        String type = getStr(args, "type", null);
        if (type == null || type.isBlank()) {
            return error("type is required");
        }
        String sev = getStr(args, "severity", "Info");
        String conf = getStr(args, "confidence", "Tentative");
        String url = getStr(args, "url", "");
        String evidence = getStr(args, "evidence", "");
        String repro = getStr(args, "repro", null);
        String full = repro == null || repro.isBlank() ? evidence : evidence + " | Repro: " + repro;
        boolean isNew = findings.addFinding(new PassiveFinding(type, sev, conf, url, full, true));
        JsonObject r = new JsonObject();
        r.addProperty("recorded", true);
        r.addProperty("new", isNew);
        r.addProperty("note", isNew ? "Added to the AI Recon findings." : "Already recorded (deduped).");
        return r;
    }

    private JsonObject compareResponses(JsonObject args) {
        Item a = resolve(getStr(args, "a_source", "proxy"), getStr(args, "a_id", null));
        Item b = resolve(getStr(args, "b_source", "proxy"), getStr(args, "b_id", null));
        if (a == null || b == null) {
            return error("Provide a_source/a_id and b_source/b_id for two captured items.");
        }
        int sa = a.response != null ? a.response.statusCode() : 0;
        int sb = b.response != null ? b.response.statusCode() : 0;
        String ba = a.response != null ? a.response.bodyToString() : "";
        String bb = b.response != null ? b.response.bodyToString() : "";
        JsonObject r = ResponseDiff.compare(sa, ba, sb, bb);
        r.addProperty("a_url", a.url);
        r.addProperty("b_url", b.url);
        return r;
    }

    // ---- oracle / hunt helpers ---------------------------------------------

    private HttpRequest injectParam(HttpRequest req, String name, String type, String value) {
        String t = type == null ? "url" : type.toLowerCase();
        if ("header".equals(t)) {
            return req.hasHeader(name) ? req.withUpdatedHeader(name, value) : req.withAddedHeader(name, value);
        }
        return req.withParameter(HttpParameter.parameter(name, value, paramType(t)));
    }

    private static HttpParameterType paramType(String t) {
        switch (t == null ? "url" : t.toLowerCase()) {
            case "body":
                return HttpParameterType.BODY;
            case "cookie":
                return HttpParameterType.COOKIE;
            case "json":
                return HttpParameterType.JSON;
            default:
                return HttpParameterType.URL;
        }
    }

    private long sendTimedMs(HttpRequest req) {
        long start = System.nanoTime();
        try {
            api.http().sendRequest(req);
        } catch (RuntimeException ignored) {
            // timing still meaningful on failure
        }
        return (System.nanoTime() - start) / 1_000_000L;
    }

    private static int statusOf(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().statusCode() : 0;
    }

    private static String bodyStr(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().bodyToString() : "";
    }

    private static JsonObject vulnFinding(String cls, String sev, String conf, String url, String param,
                                          String oracle, String evidence, String payload) {
        JsonObject o = new JsonObject();
        o.addProperty("class", cls);
        o.addProperty("vulnerable", true);
        o.addProperty("severity", sev);
        o.addProperty("confidence", conf);
        o.addProperty("url", url);
        if (param != null) {
            o.addProperty("param", param);
        }
        o.addProperty("oracle", oracle);
        o.addProperty("evidence", evidence);
        if (payload != null) {
            o.addProperty("payload", payload);
        }
        o.addProperty("note", "Verify by re-testing to kill false positives, then record with report_finding.");
        return o;
    }

    private static JsonObject notVuln(String cls, String param) {
        JsonObject o = new JsonObject();
        o.addProperty("class", cls);
        o.addProperty("vulnerable", false);
        if (param != null) {
            o.addProperty("param", param);
        }
        o.addProperty("note", "No oracle signal — inconclusive (not necessarily safe). Try another class "
                + "or oracle, or a different parameter.");
        return o;
    }

    private static double round(double v) {
        return Math.round(v * 1000.0) / 1000.0;
    }

    private static String snippetAt(String hay, int idx) {
        int start = Math.max(0, idx - 30);
        int end = Math.min(hay.length(), idx + 90);
        return hay.substring(start, end).replace("\r", " ").replace("\n", " ");
    }

    private static int countOccurrences(String hay, String needle) {
        int n = 0;
        int i = 0;
        while ((i = hay.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    private static String[] customList(JsonObject args, String key, String[] def) {
        if (args.has(key) && args.get(key).isJsonArray()) {
            JsonArray a = args.getAsJsonArray(key);
            if (a.size() > 0) {
                String[] out = new String[a.size()];
                for (int i = 0; i < a.size(); i++) {
                    out[i] = a.get(i).getAsString();
                }
                return out;
            }
        }
        return def;
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
                case "fetch_url":
                    urls.add(getStr(args, "url", ""));
                    break;
                case "fetch_common_paths":
                case "probe_paths":
                    urls.add(getStr(args, "base_url", ""));
                    break;
                case "authz_matrix":
                case "test_injection":
                case "discover_params":
                case "race_requests":
                case "graphql_introspect":
                case "test_method_tampering":
                case "test_mass_assignment":
                    try {
                        urls.add(buildRequestFromSpec(args).url());
                    } catch (RuntimeException ignored) {
                        // unresolved base
                    }
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
            case "fetch_url":
            case "fetch_common_paths":
            case "probe_paths":
            case "authz_matrix":
            case "test_injection":
            case "discover_params":
            case "race_requests":
            case "graphql_introspect":
            case "test_method_tampering":
            case "test_mass_assignment":
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
            case "fetch_url":
                return "Fetch a URL (" + getStr(args, "method", "GET")
                        + ") and extract links / JS / endpoints / secrets from the response.";
            case "fetch_common_paths":
                return "Probe common recon/misconfig paths (robots.txt, sitemap, .git, .env, "
                        + "actuator, swagger, admin, …) on the target.";
            case "probe_paths":
                return "Probe DISCOVERED site/API paths (from recon + mine_javascript) on the target "
                        + "with safe methods, and classify which are accessible / protected / missing.";
            case "authz_matrix":
                return "Replay the request as multiple identities (and unauthenticated) to test access "
                        + "control (IDOR/BOLA).";
            case "test_injection":
                return "Run an ACTIVE injection oracle (" + getStr(args, "inject_class", "?")
                        + ") against parameter '" + getStr(args, "param_name", "?") + "'.";
            case "discover_params":
                return "Brute-force hidden parameters and detect which change the response.";
            case "race_requests":
                return "Fire " + getInt(args, "count", 20) + " CONCURRENT requests (race condition test).";
            case "graphql_introspect":
                return "Send a GraphQL introspection query and check whether the schema is exposed.";
            case "test_method_tampering":
                return "Replay the request with alternate HTTP verbs (incl. PUT/PATCH/DELETE) and "
                        + "method-override headers to test for access-control / verb-tampering bypass.";
            case "test_mass_assignment":
                return "Over-post privileged fields (role/is_admin/…) onto the write request to test "
                        + "for mass-assignment; this mutates the target object.";
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
        if ("fetch_common_paths".equals(tool)) {
            return customPaths(args).length + " path probes against " + getStr(args, "base_url", "");
        }
        if ("probe_paths".equals(tool)) {
            int cap = Math.min(getInt(args, "max", 80), 200);
            return "up to " + cap + " path probes against " + getStr(args, "base_url", "")
                    + " (safe methods, in-scope only)";
        }
        if ("race_requests".equals(tool)) {
            return Math.min(getInt(args, "count", 20), 30) + " concurrent requests";
        }
        if ("discover_params".equals(tool)) {
            return "up to 60 parameter probes";
        }
        if ("test_injection".equals(tool)) {
            return "several payloads for the " + getStr(args, "inject_class", "?") + " oracle";
        }
        if ("graphql_introspect".equals(tool)) {
            return "1 introspection query";
        }
        if ("test_method_tampering".equals(tool)) {
            return Payloads.TAMPER_METHODS.length + " verb probes + "
                    + (Payloads.METHOD_OVERRIDE_HEADERS.length * 2) + " override-header probes "
                    + "(some may change state)";
        }
        if ("test_mass_assignment".equals(tool)) {
            return Payloads.MASS_ASSIGN_FIELDS.length + " privileged-field write attempts";
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
