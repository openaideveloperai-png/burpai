package com.example.burpgemini.recon;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.example.burpgemini.hunt.BbData;
import com.example.burpgemini.util.BurpContext;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Background passive scanner. Registered as a Proxy response handler, it runs cheap, deterministic
 * checks on every in-scope proxied response and records recon + findings into a {@link FindingsStore}.
 *
 * <p>It is <b>read-only</b>: it never modifies traffic and never sends anything — it only observes
 * what already flows through Burp's proxy. Work is kept fast because it runs on Burp's proxy threads;
 * anything heavier (optional AI enrichment) is handed off to {@link AiEnricher}.
 */
public final class PassiveScanner implements ProxyResponseHandler {

    private static final int MAX_BODY_SCAN = 200_000;

    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{3,}");
    private static final Pattern AWS_KEY = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----");
    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    private static final String[] ERROR_SIGNS = {
            "SQL syntax", "syntax error at or near", "ORA-0", "SQLSTATE",
            "Traceback (most recent call last)", "Exception in thread",
            "org.springframework", "java.lang.", "System.NullReferenceException",
            "<b>Warning</b>:", "<b>Fatal error</b>:", "stack trace:", "at java."
    };
    private static final String[] INTERESTING = {
            "admin", "debug", "actuator", "swagger", "graphql", "/.git", "/.env",
            "backup", "console", "phpinfo", "/api/internal", "/wp-admin"
    };
    private static final String[] URL_SECRET_PARAMS = {
            "token=", "apikey=", "api_key=", "access_token=", "auth=", "password=", "secret=", "sig="
    };

    private static final Pattern URL_HOST = Pattern.compile("https?://([A-Za-z0-9.\\-]+)");

    /** JS source-map reference: {@code //# sourceMappingURL=app.js.map} (or the older {@code //@}). */
    private static final Pattern SOURCE_MAP_REF =
            Pattern.compile("//[#@]\\s*sourceMappingURL=([^\\s'\"]+)");

    /**
     * A quoted assignment {@code name: "value"} / {@code "name":"value"} / {@code name='value'} whose
     * value is a long token — the entropy check decides if it's actually a secret.
     */
    private static final Pattern SECRET_ASSIGN = Pattern.compile(
            "[\"']?([A-Za-z0-9_.\\-]{2,40})[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9_\\-+/=.]{16,120})[\"']");

    /** Parameter name suggests the value is a variable name of a secret. */
    private static final String[] SECRET_NAME_HINTS = {
            "key", "secret", "token", "passwd", "password", "pwd", "apikey", "api_key", "auth",
            "credential", "private", "access", "session", "signature", "client_secret", "aws",
    };

    /** Redirect-target parameter names — open-redirect / SSRF candidates. */
    private static final String[] REDIRECT_PARAMS = {
            "redirect", "redirect_uri", "redirecturl", "redirect_url", "url", "next", "return",
            "returnurl", "return_url", "returnto", "return_to", "continue", "dest", "destination",
            "goto", "callback", "redir", "target", "out", "to", "forward",
    };

    private final BurpContext ctx;
    private final FindingsStore store;
    private final InfoStore info;
    private volatile AiEnricher enricher; // optional

    public PassiveScanner(BurpContext ctx, FindingsStore store, InfoStore info) {
        this.ctx = ctx;
        this.store = store;
        this.info = info;
    }

    public void setEnricher(AiEnricher enricher) {
        this.enricher = enricher;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        try {
            if (ctx.settings().isPassiveScanEnabled()) {
                analyze(response);
            }
        } catch (Exception e) {
            ctx.logError("Passive scan error: " + e);
        }
        // Never alter traffic.
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    // ------------------------------------------------------------------ analysis

    private void analyze(InterceptedResponse response) {
        HttpRequest req = response.initiatingRequest();
        if (req == null) {
            return;
        }
        String url = req.url();
        if (ctx.settings().isPassiveInScopeOnly() && !inScope(url)) {
            return;
        }

        boolean newEndpoint = store.recordEndpoint(req.method(), url, response.statusCode());
        boolean secure = req.httpService() != null && req.httpService().secure();

        // Information gathering runs on EVERY request (accumulating new values), not just once.
        String body = safeBody(response);
        gatherInfo(req, response, url, body);

        checkSecurityHeaders(response, url, secure);
        checkCookies(response, url, secure);
        checkCors(response, req, url);
        checkTechDisclosure(response, url);
        checkUrlSecrets(url);
        checkOpenRedirect(req, response, url);

        if (body != null) {
            checkBody(body, response, url);
            checkReflectedParams(req, response, body, url);
            checkSourceMap(body, response, url);
            checkGraphql(body, req, url);
            checkEntropySecrets(body, url);
            checkTakeover(body, url);
            checkMixedContent(body, response, url, secure);
            checkCacheableSensitive(body, response, url);
            checkApiDocs(body, response, url);
        }

        // Optional AI enrichment: only on newly-seen endpoints, and only when enabled.
        if (newEndpoint && enricher != null && ctx.settings().isAiEnrichEnabled()) {
            enricher.enqueue(req, response);
        }
    }

    private void checkSecurityHeaders(InterceptedResponse r, String url, boolean secure) {
        // Only meaningful for HTML documents.
        String ct = header(r, "Content-Type");
        boolean html = ct != null && ct.toLowerCase().contains("text/html");
        if (!html) {
            return;
        }
        if (header(r, "Content-Security-Policy") == null) {
            add("Missing header: Content-Security-Policy", "Low", "Firm", url,
                    "No CSP on an HTML response.");
        }
        if (secure && header(r, "Strict-Transport-Security") == null) {
            add("Missing header: Strict-Transport-Security", "Low", "Firm", url,
                    "HTTPS response without HSTS.");
        }
        if (header(r, "X-Content-Type-Options") == null) {
            add("Missing header: X-Content-Type-Options", "Info", "Firm", url, "No nosniff.");
        }
        if (header(r, "X-Frame-Options") == null && !cspHasFrameAncestors(r)) {
            add("Missing header: X-Frame-Options / frame-ancestors", "Info", "Firm", url,
                    "Page may be framable (clickjacking).");
        }
    }

    private void checkCookies(InterceptedResponse r, String url, boolean secure) {
        for (HttpHeader h : r.headers()) {
            if (!"set-cookie".equalsIgnoreCase(h.name())) {
                continue;
            }
            String v = h.value();
            String lc = v.toLowerCase();
            String name = v.contains("=") ? v.substring(0, v.indexOf('=')) : v;
            if (!lc.contains("httponly")) {
                add("Cookie without HttpOnly", "Low", "Firm", url, "Set-Cookie " + name + " lacks HttpOnly.");
            }
            if (secure && !lc.contains("secure")) {
                add("Cookie without Secure", "Low", "Firm", url, "Set-Cookie " + name + " lacks Secure on HTTPS.");
            }
            if (!lc.contains("samesite")) {
                add("Cookie without SameSite", "Info", "Tentative", url, "Set-Cookie " + name + " lacks SameSite.");
            }
        }
    }

    private void checkCors(InterceptedResponse r, HttpRequest req, String url) {
        String acao = header(r, "Access-Control-Allow-Origin");
        if (acao == null) {
            return;
        }
        boolean creds = "true".equalsIgnoreCase(header(r, "Access-Control-Allow-Credentials"));
        String origin = req.headerValue("Origin");
        if ("*".equals(acao.trim())) {
            add("CORS: wildcard Access-Control-Allow-Origin", creds ? "Medium" : "Info",
                    "Firm", url, "ACAO: * " + (creds ? "with credentials (invalid but risky)" : ""));
        } else if (origin != null && acao.trim().equalsIgnoreCase(origin.trim())) {
            add("CORS: reflected Origin", creds ? "High" : "Low", creds ? "Firm" : "Tentative", url,
                    "ACAO reflects Origin " + origin + (creds ? " with Allow-Credentials: true" : ""));
        }
    }

    private void checkTechDisclosure(InterceptedResponse r, String url) {
        String server = header(r, "Server");
        String powered = header(r, "X-Powered-By");
        if (server != null || powered != null) {
            add("Technology disclosure header", "Info", "Certain", url,
                    (server != null ? "Server: " + server + " " : "") + (powered != null ? "X-Powered-By: " + powered : ""));
        }
    }

    private void checkUrlSecrets(String url) {
        String lc = url.toLowerCase();
        for (String p : URL_SECRET_PARAMS) {
            if (lc.contains(p)) {
                add("Secret in URL query", "Medium", "Firm", url,
                        "URL carries '" + p.replace("=", "") + "' — may be logged/cached/leaked via Referer.");
                break;
            }
        }
    }

    private void checkBody(String body, InterceptedResponse r, String url) {
        String scan = body.length() > MAX_BODY_SCAN ? body.substring(0, MAX_BODY_SCAN) : body;
        if (PRIVATE_KEY.matcher(scan).find()) {
            add("Private key in response", "High", "Certain", url, "Response body contains a PRIVATE KEY block.");
        }
        if (AWS_KEY.matcher(scan).find()) {
            add("AWS access key in response", "High", "Firm", url, "Response body contains an AKIA… key.");
        }
        if (JWT.matcher(scan).find()) {
            add("JWT in response body", "Medium", "Firm", url, "Response body contains a JWT (eyJ…).");
        }
        for (String sign : ERROR_SIGNS) {
            if (scan.contains(sign)) {
                add("Verbose error / stack trace", "Medium", "Firm", url, "Response contains: " + sign);
                break;
            }
        }
        String ct = header(r, "Content-Type");
        boolean json = ct != null && ct.toLowerCase().contains("json");
        if (json) {
            String lc = scan.toLowerCase();
            if (lc.contains("\"password\"") || lc.contains("\"secret\"") || lc.contains("\"api_key\"")
                    || lc.contains("\"apikey\"")) {
                add("Sensitive field in JSON response", "Low", "Tentative", url,
                        "JSON body includes a password/secret/api_key field.");
            }
            long emails = EMAIL.matcher(scan).results().limit(5).count();
            if (emails >= 3) {
                add("Email addresses in response", "Info", "Tentative", url, "Response exposes multiple email addresses.");
            }
        }
    }

    private void checkReflectedParams(HttpRequest req, InterceptedResponse r, String body, String url) {
        String ct = header(r, "Content-Type");
        if (ct == null || !ct.toLowerCase().contains("html")) {
            return;
        }
        int checked = 0;
        for (ParsedHttpParameter p : req.parameters()) {
            if (checked >= 6) {
                break;
            }
            String val = p.value();
            if (val == null || val.length() < 4 || val.length() > 100) {
                continue;
            }
            String decoded = urlDecode(val);
            if (!decoded.chars().allMatch(c -> Character.isLetterOrDigit(c) || "-_ .".indexOf(c) >= 0)) {
                // Only flag values that could plausibly break out; skip pure alnum to reduce noise
                if (body.contains(decoded)) {
                    add("Reflected parameter (possible XSS)", "Low", "Tentative", url,
                            "Parameter '" + p.name() + "' value is reflected in the HTML response.");
                    checked++;
                }
            }
        }
    }

    /** Source maps: a served .map file leaks original source; a JS reference points to one. */
    private void checkSourceMap(String body, InterceptedResponse r, String url) {
        String lc = url.toLowerCase();
        String ct = header(r, "Content-Type");
        String cc = ct == null ? "" : ct.toLowerCase();
        // A source-map file actually being served (reveals original, pre-minified source).
        if ((lc.endsWith(".map") || lc.contains(".js.map") || lc.contains(".css.map"))
                && r.statusCode() == 200
                && body.contains("\"version\"") && (body.contains("\"sources\"") || body.contains("\"mappings\""))) {
            add("Source map exposed", "Low", "Firm", url,
                    "A .map file is served — it reconstructs the original, un-minified source.");
            return;
        }
        // A JS file pointing at its source map (the map is probably fetchable at that path).
        boolean js = cc.contains("javascript") || lc.endsWith(".js");
        if (js) {
            var m = SOURCE_MAP_REF.matcher(body);
            if (m.find()) {
                add("Source map reference in JS", "Info", "Firm", url,
                        "JS references sourceMappingURL=" + trim(m.group(1), 80)
                        + " — fetch it to recover original source.");
            }
        }
    }

    /** GraphQL: flag the endpoint, and passively catch introspection/field-suggestion left enabled. */
    private void checkGraphql(String body, HttpRequest req, String url) {
        String lc = url.toLowerCase();
        boolean pathIsGraphql = lc.contains("/graphql") || lc.contains("/gql") || lc.endsWith("/query");
        boolean bodyLooksGraphql = body.contains("\"data\"") && body.contains("\"errors\"")
                || body.contains("__schema") || body.contains("__typename");
        if (!pathIsGraphql && !bodyLooksGraphql) {
            return;
        }
        info.addTech("GraphQL endpoint: " + FindingsStore.endpointSignature(url));
        if (body.contains("__schema") && body.contains("\"types\"")) {
            add("GraphQL introspection enabled", "Medium", "Firm", url,
                    "Response exposes the GraphQL schema (__schema/types) — maps the full API surface.");
        } else if (body.contains("Did you mean") || body.contains("Cannot query field")) {
            add("GraphQL field suggestions enabled", "Low", "Tentative", url,
                    "GraphQL 'Did you mean'/field-suggestion errors let an attacker infer the schema.");
        } else {
            add("GraphQL endpoint", "Info", "Firm", url,
                    "GraphQL endpoint detected — test authorization per-field/object (BOLA), batching and "
                    + "alias-based rate-limit bypass; try introspection.");
        }
    }

    /** High-entropy tokens assigned to secret-looking names in JS/JSON — likely hard-coded keys. */
    private void checkEntropySecrets(String body, String url) {
        String scan = body.length() > MAX_BODY_SCAN ? body.substring(0, MAX_BODY_SCAN) : body;
        var m = SECRET_ASSIGN.matcher(scan);
        int flagged = 0;
        int scanned = 0;
        while (m.find() && scanned++ < 4000 && flagged < 5) {
            String name = m.group(1);
            String value = m.group(2);
            String ln = name.toLowerCase();
            boolean nameHints = false;
            for (String h : SECRET_NAME_HINTS) {
                if (ln.contains(h)) {
                    nameHints = true;
                    break;
                }
            }
            if (!nameHints) {
                continue;
            }
            // Skip obvious non-secrets: URLs, dotted paths, MIME types, all-lowercase words.
            if (value.contains("/") && value.contains(".") || value.startsWith("http")) {
                continue;
            }
            if (shannon(value) >= 3.6 && hasMixedClasses(value)) {
                add("Hard-coded secret (high entropy)", "Medium", "Tentative", url,
                        "'" + name + "' = a " + value.length() + "-char high-entropy token ("
                        + mask(value) + ") — verify it's a live credential.");
                info.recordSecret("High-entropy '" + name + "'", value, url);
                flagged++;
            }
        }
    }

    /** Redirect-target params that reflect into a Location header (open redirect) or carry a URL value. */
    private void checkOpenRedirect(HttpRequest req, InterceptedResponse r, String url) {
        String location = header(r, "Location");
        int status = r.statusCode();
        boolean redirect = status >= 300 && status < 400 && location != null;
        int flagged = 0;
        for (ParsedHttpParameter p : req.parameters()) {
            if (flagged >= 3) {
                break;
            }
            String pn = p.name() == null ? "" : p.name().toLowerCase();
            boolean isRedirParam = false;
            for (String rp : REDIRECT_PARAMS) {
                if (pn.equals(rp)) {
                    isRedirParam = true;
                    break;
                }
            }
            if (!isRedirParam) {
                continue;
            }
            String val = urlDecode(p.value() == null ? "" : p.value());
            boolean urlish = val.startsWith("http://") || val.startsWith("https://")
                    || val.startsWith("//") || val.startsWith("/\\") || val.startsWith("/");
            if (redirect && !val.isEmpty() && (location.contains(val) || location.equalsIgnoreCase(val))) {
                add("Open redirect (reflected in Location)", "Medium", "Firm", url,
                        "Param '" + p.name() + "'=" + trim(val, 60) + " is reflected into the "
                        + status + " Location header.");
                flagged++;
            } else if (urlish) {
                add("Open-redirect-prone parameter", "Info", "Tentative", url,
                        "Param '" + p.name() + "' takes a URL/path (" + trim(val, 60)
                        + ") — test for open redirect / SSRF.");
                flagged++;
            }
        }
    }

    /** Subdomain-takeover: an orphan-provider fingerprint in the body. */
    private void checkTakeover(String body, String url) {
        String scan = body.length() > 20_000 ? body.substring(0, 20_000) : body;
        for (String[] fp : BbData.TAKEOVER_FINGERPRINTS) {
            if (scan.contains(fp[0])) {
                add("Subdomain takeover candidate (" + fp[1] + ")", "High", "Tentative", url,
                        "Orphan fingerprint \"" + fp[0] + "\" — confirm dangling DNS (dig CNAME).");
                break;
            }
        }
    }

    /** Mixed content: an HTTPS page loading http:// scripts/resources. */
    private void checkMixedContent(String body, InterceptedResponse r, String url, boolean secure) {
        if (!secure) {
            return;
        }
        String ct = header(r, "Content-Type");
        if (ct == null || !ct.toLowerCase().contains("html")) {
            return;
        }
        String scan = body.length() > MAX_BODY_SCAN ? body.substring(0, MAX_BODY_SCAN) : body;
        if (scan.contains("src=\"http://") || scan.contains("src='http://")
                || scan.contains("href=\"http://") && scan.contains("stylesheet")) {
            add("Mixed content on HTTPS page", "Low", "Firm", url,
                    "HTTPS page references http:// resources — MITM/injection risk.");
        }
    }

    /** A cacheable response that also carries sensitive/authenticated data. */
    private void checkCacheableSensitive(String body, InterceptedResponse r, String url) {
        String cc = header(r, "Cache-Control");
        String lc = cc == null ? "" : cc.toLowerCase();
        boolean cacheable = (lc.contains("public") || lc.contains("max-age") || lc.contains("s-maxage"))
                && !lc.contains("no-store") && !lc.contains("private") && !lc.contains("no-cache");
        boolean cachedHit = header(r, "Age") != null || header(r, "X-Cache") != null
                || header(r, "CF-Cache-Status") != null;
        if (!cacheable && !cachedHit) {
            return;
        }
        String bl = body.length() > 40_000 ? body.substring(0, 40_000).toLowerCase() : body.toLowerCase();
        boolean sensitive = bl.contains("\"email\"") || bl.contains("\"token\"") || bl.contains("\"api_key\"")
                || bl.contains("authorization") || bl.contains("set-cookie") || bl.contains("\"ssn\"")
                || bl.contains("\"password\"");
        boolean personalized = header(r, "Set-Cookie") != null;
        if (sensitive || personalized) {
            add("Cacheable sensitive response", "Medium", "Tentative", url,
                    "Response is cacheable (" + (cc == null ? "cache hit indicators" : cc)
                    + ") yet appears to carry user/sensitive data — cache-deception / data-leak risk.");
        }
    }

    /** Exposed API documentation (Swagger/OpenAPI) — a full map of the API surface. */
    private void checkApiDocs(String body, InterceptedResponse r, String url) {
        String head = body.length() > 4000 ? body.substring(0, 4000) : body;
        if (head.contains("\"swagger\":\"2.0\"") || head.contains("\"openapi\":\"3")
                || head.contains("\"openapi\": \"3") || head.contains("swagger-ui")
                || head.contains("SwaggerUIBundle")) {
            add("Exposed API documentation (Swagger/OpenAPI)", "Low", "Firm", url,
                    "OpenAPI/Swagger spec or UI is reachable — enumerates every endpoint & parameter.");
        }
    }

    // ---- small numeric/text helpers for the detectors above ----------------

    /** Shannon entropy (bits/char) of a string — a cheap "does this look random?" signal. */
    private static double shannon(String s) {
        if (s == null || s.isEmpty()) {
            return 0;
        }
        int[] counts = new int[128];
        int total = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) {
                counts[c]++;
                total++;
            }
        }
        double h = 0;
        for (int c : counts) {
            if (c > 0) {
                double pr = (double) c / total;
                h -= pr * (Math.log(pr) / Math.log(2));
            }
        }
        return h;
    }

    /** True if the token mixes character classes (upper/lower/digit) — filters out dictionary words. */
    private static boolean hasMixedClasses(String s) {
        boolean up = false;
        boolean lo = false;
        boolean di = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isUpperCase(c)) {
                up = true;
            } else if (Character.isLowerCase(c)) {
                lo = true;
            } else if (Character.isDigit(c)) {
                di = true;
            }
        }
        return (up && di) || (lo && di) || (up && lo && di);
    }

    private static String mask(String s) {
        if (s.length() <= 8) {
            return s.charAt(0) + "…";
        }
        return s.substring(0, 4) + "…" + s.substring(s.length() - 3);
    }

    private static String trim(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    // ------------------------------------------------------------------ information gathering

    /** Mine one request/response for recon facts. Runs on EVERY request; values accumulate. */
    private void gatherInfo(HttpRequest req, InterceptedResponse resp, String url, String body) {
        String sig = FindingsStore.endpointSignature(url);
        if (req.httpService() != null) {
            info.addHost(req.httpService().host());
        }

        int pc = 0;
        for (ParsedHttpParameter p : req.parameters()) {
            if (pc++ > 250) {
                break;
            }
            info.recordParam(p.name(), p.type().name(), p.value(), sig);
        }

        for (HttpHeader h : req.headers()) {
            String n = h.name();
            if (n == null) {
                continue;
            }
            String ln = n.toLowerCase();
            if (ln.equals("authorization")) {
                info.recordReqHeader(n, InfoStore.mask(h.value()));
                extractAuthSecret(h.value(), url);
            } else if (ln.equals("cookie")) {
                info.recordReqHeader(n, "(cookies)");
                for (String c : h.value().split(";")) {
                    int eq = c.indexOf('=');
                    String cn = (eq > 0 ? c.substring(0, eq) : c).trim();
                    if (!cn.isEmpty()) {
                        info.recordCookie(cn, "request");
                    }
                }
            } else {
                info.recordReqHeader(n, interestingHeader(ln) ? h.value() : null);
            }
        }

        for (HttpHeader h : resp.headers()) {
            String n = h.name();
            if (n == null) {
                continue;
            }
            String ln = n.toLowerCase();
            if (ln.equals("set-cookie")) {
                String v = h.value();
                String cn = (v.contains("=") ? v.substring(0, v.indexOf('=')) : v).trim();
                info.recordCookie(cn, cookieAttrs(v));
            } else {
                info.recordRespHeader(n, interestingHeader(ln) ? h.value() : null);
            }
            if (ln.equals("server") || ln.equals("x-powered-by") || ln.equals("x-aspnet-version")
                    || ln.equals("x-generator") || ln.equals("via") || ln.equals("x-runtime")) {
                info.addTech(n + ": " + h.value());
            }
        }

        if (body != null) {
            String scan = body.length() > MAX_BODY_SCAN ? body.substring(0, MAX_BODY_SCAN) : body;
            find(JWT, scan, 10, m -> info.recordSecret("JWT", m, url));
            find(AWS_KEY, scan, 5, m -> info.recordSecret("AWS key", m, url));
            if (PRIVATE_KEY.matcher(scan).find()) {
                info.recordSecret("Private key", "-----BEGIN PRIVATE KEY----- (in " + url + ")", url);
            }
            find(EMAIL, scan, 25, info::addEmail);
            var hm = URL_HOST.matcher(scan);
            int hc = 0;
            while (hm.find() && hc++ < 40) {
                info.addHost(hm.group(1));
            }
        }
    }

    private void extractAuthSecret(String value, String url) {
        if (value == null) {
            return;
        }
        String v = value.trim();
        if (v.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = v.substring(7).trim();
            String kind = JWT.matcher(token).matches() || token.startsWith("eyJ") ? "JWT (Bearer)" : "Bearer token";
            info.recordSecret(kind, token, url);
        } else if (v.regionMatches(true, 0, "Basic ", 0, 6)) {
            info.recordSecret("Basic auth", v.substring(6).trim(), url);
        } else if (v.length() >= 12) {
            info.recordSecret("Authorization", v, url);
        }
    }

    private static void find(Pattern p, String hay, int limit, java.util.function.Consumer<String> sink) {
        var m = p.matcher(hay);
        int n = 0;
        while (m.find() && n++ < limit) {
            sink.accept(m.group());
        }
    }

    private static boolean interestingHeader(String lowerName) {
        switch (lowerName) {
            case "content-type":
            case "location":
            case "server":
            case "x-powered-by":
            case "www-authenticate":
            case "user-agent":
            case "referer":
            case "origin":
            case "cache-control":
            case "content-security-policy":
            case "access-control-allow-origin":
            case "access-control-allow-credentials":
            case "x-request-id":
            case "x-forwarded-for":
            case "x-requested-with":
                return true;
            default:
                return lowerName.startsWith("x-") || lowerName.startsWith("access-control")
                        || lowerName.startsWith("sec-");
        }
    }

    private static String cookieAttrs(String setCookieValue) {
        String lc = setCookieValue.toLowerCase();
        StringBuilder sb = new StringBuilder();
        if (lc.contains("httponly")) {
            sb.append("HttpOnly ");
        }
        if (lc.contains("secure")) {
            sb.append("Secure ");
        }
        int ss = lc.indexOf("samesite");
        if (ss >= 0) {
            int end = lc.indexOf(';', ss);
            sb.append(setCookieValue.substring(ss, end < 0 ? Math.min(setCookieValue.length(), ss + 20) : end).trim()).append(' ');
        }
        return sb.toString().trim();
    }

    // ------------------------------------------------------------------ helpers

    private void add(String type, String sev, String conf, String url, String evidence) {
        boolean isNew = store.addFinding(new PassiveFinding(type, sev, conf, url, evidence, false));
        if (isNew) {
            ctx.logInfo("[passive] " + sev + " — " + type + " @ " + url);
        }
    }

    private boolean cspHasFrameAncestors(InterceptedResponse r) {
        String csp = header(r, "Content-Security-Policy");
        return csp != null && csp.toLowerCase().contains("frame-ancestors");
    }

    private static String header(InterceptedResponse r, String name) {
        try {
            return r.hasHeader(name) ? r.headerValue(name) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private String safeBody(InterceptedResponse r) {
        try {
            String mime = r.mimeType() == null ? "" : r.mimeType().toString().toLowerCase();
            String ct = header(r, "Content-Type");
            String cc = ct == null ? "" : ct.toLowerCase();
            boolean texty = cc.contains("html") || cc.contains("json") || cc.contains("xml")
                    || cc.contains("javascript") || cc.contains("text") || mime.contains("json")
                    || mime.contains("html") || mime.contains("script");
            if (!texty) {
                return null;
            }
            return r.bodyToString();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private boolean inScope(String url) {
        try {
            return ctx.api().scope().isInScope(url);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return s;
        }
    }

    /** For endpoint listing helpers that need the parameter list length elsewhere. */
    static int paramCount(List<ParsedHttpParameter> params) {
        return params == null ? 0 : params.size();
    }
}
