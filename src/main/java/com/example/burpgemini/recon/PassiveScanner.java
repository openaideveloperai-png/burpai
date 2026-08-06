package com.example.burpgemini.recon;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
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

        if (body != null) {
            checkBody(body, response, url);
            checkReflectedParams(req, response, body, url);
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
