package com.example.burpgemini.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deep static miner for JavaScript (and JSON config) bodies. Purely local — it never sends traffic;
 * it reads content already captured and pulls out everything worth a closer look:
 *
 * <ul>
 *   <li><b>Secrets</b> — vendor-specific tokens (AWS/GCP/Google/Slack/Stripe/GitHub/GitLab/Twilio/
 *       SendGrid/npm), JWTs, private keys, basic-auth URLs, and generic high-entropy assignments.</li>
 *   <li><b>Endpoints</b> — quoted API paths and {@code fetch/axios/XHR} call targets.</li>
 *   <li><b>Debug / feature flags</b> — {@code debug}, {@code __DEV__}, {@code bypassAuth}, feature
 *       flags, staging/sandbox/mock switches left in production bundles.</li>
 *   <li><b>Dangerous sinks</b> — {@code eval}, {@code innerHTML}, {@code document.write},
 *       {@code postMessage}, {@code dangerouslySetInnerHTML}, and other DOM-XSS sinks.</li>
 *   <li><b>Insecure patterns</b> — disabled TLS verification, {@code Math.random()} tokens, hard-coded
 *       CORS wildcards, disabled CSRF, prototype-pollution hints.</li>
 *   <li><b>Interesting hosts</b> — localhost / RFC-1918 / *.internal / staging|dev|test / cloud
 *       buckets — and noteworthy comments (TODO/FIXME/HACK/password/…).</li>
 * </ul>
 *
 * <p>Everything is bounded and secret values are masked. The result includes a prioritized
 * {@code vuln_leads} array so the agent knows what to test next.
 */
public final class JsMiner {

    private JsMiner() {
    }

    private static final int MAX_SCAN = 800_000;
    private static final int CAP = 60;

    /** A named secret pattern. */
    private record Sig(String label, Pattern pattern, boolean maskGroup1) {
    }

    // ---- vendor & generic secret signatures --------------------------------

    private static final List<Sig> SECRET_SIGS = List.of(
            new Sig("AWS access key id", Pattern.compile("AKIA[0-9A-Z]{16}"), false),
            new Sig("AWS session/temp key", Pattern.compile("ASIA[0-9A-Z]{16}"), false),
            new Sig("Google API key", Pattern.compile("AIza[0-9A-Za-z_\\-]{35}"), false),
            new Sig("Google OAuth client", Pattern.compile("[0-9]+-[0-9A-Za-z_]{20,}\\.apps\\.googleusercontent\\.com"), false),
            new Sig("Slack token", Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,48}"), false),
            new Sig("Slack webhook", Pattern.compile("https://hooks\\.slack\\.com/services/[A-Za-z0-9/]+"), false),
            new Sig("Stripe secret/live key", Pattern.compile("(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"), false),
            new Sig("Stripe publishable key", Pattern.compile("pk_(?:live|test)_[0-9A-Za-z]{16,}"), false),
            new Sig("GitHub token", Pattern.compile("gh[pousr]_[0-9A-Za-z]{36,}"), false),
            new Sig("GitLab PAT", Pattern.compile("glpat-[0-9A-Za-z_\\-]{20}"), false),
            new Sig("Twilio API key", Pattern.compile("SK[0-9a-fA-F]{32}"), false),
            new Sig("Twilio account SID", Pattern.compile("AC[0-9a-fA-F]{32}"), false),
            new Sig("SendGrid key", Pattern.compile("SG\\.[0-9A-Za-z_\\-]{16,}\\.[0-9A-Za-z_\\-]{16,}"), false),
            new Sig("Mailgun key", Pattern.compile("key-[0-9a-zA-Z]{32}"), false),
            new Sig("npm token", Pattern.compile("npm_[0-9A-Za-z]{36}"), false),
            new Sig("Square token", Pattern.compile("sq0(?:atp|csp)-[0-9A-Za-z_\\-]{22,}"), false),
            new Sig("Heroku/UUID-ish key", Pattern.compile("(?i)heroku[a-z0-9_ -]{0,15}[:=][^\\n]{0,5}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), false),
            new Sig("JWT", Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{3,}"), false),
            new Sig("Private key block", Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"), false),
            new Sig("Basic-auth in URL", Pattern.compile("https?://[^/\\s:@\"']+:[^/\\s:@\"']+@[A-Za-z0-9.\\-]+"), false)
    );

    /** name-hinted assignment: value entropy decides whether it's really a secret. */
    private static final Pattern SECRET_ASSIGN = Pattern.compile(
            "(?i)([A-Za-z0-9_.\\-]*(?:api[_-]?key|secret|token|passwd|password|pwd|auth|credential|private[_-]?key"
            + "|client[_-]?secret|access[_-]?key|encryption[_-]?key|signing[_-]?key)[A-Za-z0-9_.\\-]*)"
            + "[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9_\\-+/=.]{12,120})[\"']");

    private static final Pattern ENDPOINT_QUOTED = Pattern.compile(
            "[\"'`](/(?:api|v\\d+|graphql|gql|rest|internal|admin|auth|oauth|token|user|users|account|accounts"
            + "|session|login|logout|signup|register|password|reset|upload|download|file|files|export|import"
            + "|payment|payments|order|orders|invoice|webhook|callback|search|config|settings|debug|test)"
            + "[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%\\-]*)[\"'`]");

    private static final Pattern CALL_URL = Pattern.compile(
            "(?i)(?:fetch|axios(?:\\.\\w+)?|\\.(?:get|post|put|delete|patch|ajax|open|request)|XMLHttpRequest[^;]{0,40}\\.open)"
            + "\\s*\\(\\s*[\"'`]([^\"'`]{1,200})[\"'`]");

    private static final Pattern ABS_URL = Pattern.compile("https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%\\-]+");

    private static final Pattern FLAG_ASSIGN = Pattern.compile(
            "(?i)\\b([A-Za-z0-9_$.]*(?:debug|verbose|dev[_-]?mode|__dev__|is[_-]?test|test[_-]?mode|staging"
            + "|sandbox|mock|feature[_-]?flag|admin[_-]?mode|god[_-]?mode|bypass[_-]?auth|skip[_-]?auth"
            + "|disable[_-]?auth|disable[_-]?csrf|allow[_-]?all|unsafe|insecure|experimental)[A-Za-z0-9_$]*)"
            + "\\s*[:=]\\s*(true|1|\"?on\"?|\"?yes\"?)\\b");

    private static final String[] SINKS = {
            "eval(", "new Function(", "Function(", ".innerHTML", ".outerHTML", "document.write",
            "insertAdjacentHTML", "dangerouslySetInnerHTML", "setTimeout(\"", "setTimeout('",
            "setInterval(\"", "setInterval('", ".html(", "document.cookie", "localStorage.setItem",
            "sessionStorage.setItem", "location.href", "location.assign", "location.replace",
            "window.open(", "postMessage(", "srcdoc", "v-html", "$sanitize",
    };

    /** Insecure code smells -> {regex, label, severity}. */
    private static final Object[][] INSECURE = {
            {Pattern.compile("(?i)rejectUnauthorized\\s*:\\s*false"), "TLS verification disabled (rejectUnauthorized:false)", "High"},
            {Pattern.compile("(?i)(?:strictSSL|verify|checkServerIdentity)\\s*:\\s*false"), "TLS/host verification disabled", "High"},
            {Pattern.compile("NODE_TLS_REJECT_UNAUTHORIZED"), "NODE_TLS_REJECT_UNAUTHORIZED referenced (TLS bypass)", "Medium"},
            {Pattern.compile("(?i)Access-Control-Allow-Origin[\"']?\\s*[:,]\\s*[\"']\\*"), "CORS wildcard set in client code", "Low"},
            {Pattern.compile("(?i)(?:csrf|xsrf)[A-Za-z]*\\s*[:=]\\s*(?:false|0|['\"]off)"), "CSRF protection disabled in code", "Medium"},
            {Pattern.compile("(?i)Math\\.random\\(\\)[^;\\n]{0,40}(?:token|id|uuid|nonce|otp|password|secret|session)"), "Weak randomness (Math.random) for a token/id", "Medium"},
            {Pattern.compile("(?i)(?:token|id|uuid|nonce|otp|secret|session)[^;\\n]{0,40}Math\\.random\\(\\)"), "Weak randomness (Math.random) for a token/id", "Medium"},
            {Pattern.compile("__proto__|constructor\\s*\\[\\s*[\"']prototype|prototype\\s*\\["), "Prototype-pollution pattern", "Low"},
            {Pattern.compile("(?i)addEventListener\\(\\s*[\"']message[\"']"), "postMessage handler (check origin validation)", "Low"},
            {Pattern.compile("(?i)(?:password|passwd|pwd)\\s*[:=]\\s*[\"'][^\"']{3,}[\"']"), "Hard-coded password literal", "High"},
            {Pattern.compile("(?i)authorization\\s*[:=]\\s*[\"'](?:bearer|basic)\\s+[^\"']{8,}[\"']"), "Hard-coded Authorization header", "High"},
    };

    private static final Pattern COMMENT_LINE = Pattern.compile("//[^\\n]{0,300}");
    private static final Pattern COMMENT_BLOCK = Pattern.compile("/\\*(.*?)\\*/", Pattern.DOTALL);
    private static final Pattern COMMENT_KEYWORDS = Pattern.compile(
            "(?i)\\b(todo|fixme|hack|xxx|bug|workaround|temporary|temp|remove|deprecated|insecure|"
            + "vulnerab|password|passwd|secret|apikey|api key|token|backdoor|do not|don't|hardcod|test only)\\b");

    private static final Pattern INTERNAL_HOST = Pattern.compile(
            "(?i)\\b(?:localhost|127\\.0\\.0\\.1|10(?:\\.\\d{1,3}){3}|192\\.168(?:\\.\\d{1,3}){2}"
            + "|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}|[A-Za-z0-9.\\-]+\\.(?:internal|local|corp|intranet)"
            + "|(?:staging|dev|test|qa|uat|preprod|internal|admin)[.\\-][A-Za-z0-9.\\-]+)\\b");

    private static final Pattern CLOUD_BUCKET = Pattern.compile(
            "(?i)[A-Za-z0-9.\\-]*(?:s3[.\\-][A-Za-z0-9.\\-]*amazonaws\\.com|[A-Za-z0-9\\-]+\\.s3\\.amazonaws\\.com"
            + "|storage\\.googleapis\\.com|[A-Za-z0-9\\-]+\\.blob\\.core\\.windows\\.net|[A-Za-z0-9\\-]+\\.firebaseio\\.com"
            + "|[A-Za-z0-9\\-]+\\.cloudfront\\.net|[A-Za-z0-9\\-]+\\.digitaloceanspaces\\.com)[A-Za-z0-9._/\\-]*");

    private static final Pattern WEBSOCKET = Pattern.compile("wss?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%\\-]+");
    private static final Pattern GRAPHQL_OP = Pattern.compile("(?i)\\b(query|mutation|subscription)\\s+[A-Za-z_][A-Za-z0-9_]*\\s*[({]");

    // ------------------------------------------------------------------------

    /** Mine one JS/JSON body. {@code url} is only used for labelling. */
    public static JsonObject mine(String js, String url) {
        JsonObject out = new JsonObject();
        out.addProperty("url", url == null ? "" : url);
        if (js == null || js.isEmpty()) {
            out.addProperty("note", "Empty body.");
            return out;
        }
        String scan = js.length() > MAX_SCAN ? js.substring(0, MAX_SCAN) : js;
        List<JsonObject> leads = new ArrayList<>();

        // --- secrets ---
        JsonArray secrets = new JsonArray();
        for (Sig sig : SECRET_SIGS) {
            Matcher m = sig.pattern().matcher(scan);
            int n = 0;
            while (m.find() && n++ < 12) {
                String hit = m.group();
                secrets.add(sig.label() + ": " + mask(hit));
                String sev = severeSecret(sig.label()) ? "High" : "Medium";
                addLead(leads, "Exposed secret — " + sig.label(), sev, mask(hit));
            }
        }
        Set<String> genericSecrets = new LinkedHashSet<>();
        Matcher gm = SECRET_ASSIGN.matcher(scan);
        int gsScanned = 0;
        while (gm.find() && genericSecrets.size() < 25 && gsScanned++ < 6000) {
            String name = gm.group(1);
            String val = gm.group(2);
            if (val.startsWith("http") || (val.contains("/") && val.contains(".")) || looksLikePlaceholder(val)) {
                continue;
            }
            if (shannon(val) >= 3.4 && mixedClasses(val)) {
                genericSecrets.add(name + " = " + mask(val));
                addLead(leads, "Hard-coded secret assignment", "Medium", name + " = " + mask(val));
            }
        }
        for (String s : genericSecrets) {
            secrets.add(s);
        }
        out.add("secrets", secrets);

        // --- endpoints & calls ---
        Set<String> endpoints = new LinkedHashSet<>();
        addAll(ENDPOINT_QUOTED.matcher(scan), 1, endpoints, CAP);
        Set<String> calls = new LinkedHashSet<>();
        addAll(CALL_URL.matcher(scan), 1, calls, CAP);
        Set<String> urls = new LinkedHashSet<>();
        addAll(ABS_URL.matcher(scan), 0, urls, CAP);
        out.add("endpoints", toArr(endpoints));
        out.add("api_calls", toArr(calls));
        out.add("absolute_urls", toArr(urls));

        // --- debug / feature flags ---
        Set<String> flags = new LinkedHashSet<>();
        Matcher fm = FLAG_ASSIGN.matcher(scan);
        while (fm.find() && flags.size() < 40) {
            String hit = (fm.group(1) + " = " + fm.group(2)).trim();
            flags.add(hit);
        }
        out.add("debug_feature_flags", toArr(flags));
        if (!flags.isEmpty()) {
            addLead(leads, "Debug/feature flag enabled in bundle", "Low",
                    String.join("; ", capList(flags, 5)));
        }

        // --- dangerous sinks ---
        JsonArray sinks = new JsonArray();
        for (String s : SINKS) {
            int c = count(scan, s);
            if (c > 0) {
                JsonObject o = new JsonObject();
                o.addProperty("sink", s);
                o.addProperty("count", c);
                sinks.add(o);
            }
        }
        out.add("dangerous_sinks", sinks);
        if (sinks.size() > 0) {
            addLead(leads, "DOM-XSS sinks present", "Medium",
                    "Trace whether user-controlled sources (location/hash/name/postMessage/query) reach: "
                    + sinkNames(sinks));
        }

        // --- insecure patterns ---
        JsonArray insecure = new JsonArray();
        for (Object[] row : INSECURE) {
            Pattern p = (Pattern) row[0];
            if (p.matcher(scan).find()) {
                String label = (String) row[1];
                String sev = (String) row[2];
                insecure.add(label);
                addLead(leads, label, sev, "matched in " + shortUrl(url));
            }
        }
        out.add("insecure_patterns", insecure);

        // --- hosts, buckets, sockets, graphql ---
        Set<String> internal = new LinkedHashSet<>();
        addAll(INTERNAL_HOST.matcher(scan), 0, internal, 40);
        out.add("internal_hosts", toArr(internal));
        if (!internal.isEmpty()) {
            addLead(leads, "Internal/staging host referenced", "Low", String.join(", ", capList(internal, 6)));
        }
        Set<String> buckets = new LinkedHashSet<>();
        addAll(CLOUD_BUCKET.matcher(scan), 0, buckets, 30);
        out.add("cloud_buckets", toArr(buckets));
        if (!buckets.isEmpty()) {
            addLead(leads, "Cloud storage bucket referenced", "Low",
                    "Check for public/misconfigured access: " + String.join(", ", capList(buckets, 5)));
        }
        Set<String> sockets = new LinkedHashSet<>();
        addAll(WEBSOCKET.matcher(scan), 0, sockets, 20);
        out.add("websockets", toArr(sockets));
        Set<String> gql = new LinkedHashSet<>();
        addAll(GRAPHQL_OP.matcher(scan), 0, gql, 30);
        out.add("graphql_operations", toArr(gql));

        // --- interesting comments ---
        Set<String> comments = new LinkedHashSet<>();
        collectComments(COMMENT_LINE.matcher(scan), comments);
        Matcher cb = COMMENT_BLOCK.matcher(scan);
        int bc = 0;
        while (cb.find() && bc++ < 200 && comments.size() < 40) {
            String c = cb.group(1).trim().replaceAll("\\s+", " ");
            if (c.length() >= 4 && c.length() < 300 && COMMENT_KEYWORDS.matcher(c).find()) {
                comments.add(c);
            }
        }
        out.add("interesting_comments", toArr(comments));

        // --- prioritized leads + summary ---
        leads.sort((a, b) -> sevRank(b.get("severity").getAsString()) - sevRank(a.get("severity").getAsString()));
        JsonArray leadArr = new JsonArray();
        for (JsonObject l : capObjs(leads, 40)) {
            leadArr.add(l);
        }
        out.add("vuln_leads", leadArr);

        JsonObject summary = new JsonObject();
        summary.addProperty("secrets", secrets.size());
        summary.addProperty("endpoints", endpoints.size() + calls.size());
        summary.addProperty("debug_flags", flags.size());
        summary.addProperty("dangerous_sinks", sinks.size());
        summary.addProperty("insecure_patterns", insecure.size());
        summary.addProperty("leads", leadArr.size());
        out.add("summary", summary);
        out.addProperty("note", "Static analysis only. Next: fetch source maps if referenced, test the "
                + "discovered endpoints (auth/IDOR/injection) with the active tools, and verify each secret "
                + "is live before reporting.");
        return out;
    }

    // ---- helpers -----------------------------------------------------------

    private static boolean severeSecret(String label) {
        String l = label.toLowerCase();
        return l.contains("private key") || l.contains("aws") || l.contains("stripe secret")
                || l.contains("github") || l.contains("gitlab") || l.contains("basic-auth")
                || l.contains("slack token") || l.contains("sendgrid") || l.contains("twilio");
    }

    private static boolean looksLikePlaceholder(String v) {
        String l = v.toLowerCase();
        return l.contains("your") || l.contains("xxx") || l.contains("example") || l.contains("placeholder")
                || l.contains("changeme") || l.contains("<") || l.contains("test_test") || l.matches("[*x.]{6,}");
    }

    private static void addLead(List<JsonObject> leads, String type, String severity, String evidence) {
        JsonObject o = new JsonObject();
        o.addProperty("type", type);
        o.addProperty("severity", severity);
        o.addProperty("evidence", evidence.length() > 200 ? evidence.substring(0, 200) + "…" : evidence);
        leads.add(o);
    }

    private static void collectComments(Matcher m, Set<String> into) {
        int n = 0;
        while (m.find() && n++ < 3000 && into.size() < 40) {
            String c = m.group().substring(2).trim();
            if (c.length() >= 4 && c.length() < 300 && COMMENT_KEYWORDS.matcher(c).find()) {
                into.add(c);
            }
        }
    }

    private static void addAll(Matcher m, int group, Set<String> into, int cap) {
        while (m.find() && into.size() < cap) {
            String v = m.group(group);
            if (v != null && !v.isBlank()) {
                into.add(v.length() > 200 ? v.substring(0, 200) + "…" : v);
            }
        }
    }

    private static int count(String hay, String needle) {
        int n = 0;
        int i = 0;
        while ((i = hay.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    private static String sinkNames(JsonArray sinks) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (var el : sinks) {
            if (n++ >= 6) {
                break;
            }
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(el.getAsJsonObject().get("sink").getAsString());
        }
        return sb.toString();
    }

    private static int sevRank(String s) {
        switch (s) {
            case "High": return 3;
            case "Medium": return 2;
            case "Low": return 1;
            default: return 0;
        }
    }

    private static List<String> capList(Set<String> set, int n) {
        List<String> out = new ArrayList<>();
        for (String s : set) {
            if (out.size() >= n) {
                break;
            }
            out.add(s);
        }
        return out;
    }

    private static List<JsonObject> capObjs(List<JsonObject> list, int n) {
        return list.size() <= n ? list : list.subList(0, n);
    }

    private static JsonArray toArr(Set<String> set) {
        JsonArray a = new JsonArray();
        for (String s : set) {
            a.add(s);
        }
        return a;
    }

    private static String shortUrl(String url) {
        if (url == null) {
            return "the file";
        }
        int q = url.indexOf('?');
        return q > 0 ? url.substring(0, q) : url;
    }

    static double shannon(String s) {
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

    static boolean mixedClasses(String s) {
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

    private static String mask(String v) {
        if (v == null) {
            return "";
        }
        if (v.length() <= 10) {
            return v.charAt(0) + "***";
        }
        return v.substring(0, 6) + "…" + v.substring(v.length() - 4) + " (len " + v.length() + ")";
    }
}
