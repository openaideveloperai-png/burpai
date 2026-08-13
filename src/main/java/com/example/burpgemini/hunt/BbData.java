package com.example.burpgemini.hunt;

/**
 * Static payload libraries, fingerprints and header lists for the bug-bounty tools. Grounded in
 * current (2025–2026) methodology: PortSwigger web-cache-poisoning research, HackTricks CORS bypass,
 * the can-i-take-over-xyz subdomain-takeover fingerprints, and common WAF signatures.
 */
public final class BbData {

    private BbData() {
    }

    // ---- Subdomain takeover: response-body fingerprint -> service ----------
    // {fingerprint substring, service name}. A dangling CNAME to an unclaimed provider returns one
    // of these orphan pages.
    public static final String[][] TAKEOVER_FINGERPRINTS = {
            {"NoSuchBucket", "AWS S3"},
            {"The specified bucket does not exist", "AWS S3"},
            {"There isn't a GitHub Pages site here", "GitHub Pages"},
            {"herokucdn.com/error-pages/no-such-app.html", "Heroku"},
            {"No such app", "Heroku"},
            {"Fastly error: unknown domain", "Fastly"},
            {"The feed has not been found", "FeedPress"},
            {"Sorry, this shop is currently unavailable", "Shopify"},
            {"Whatever you were looking for doesn't currently exist at this address", "Tumblr"},
            {"Do you want to register", "WordPress"},
            {"project not found", "Surge.sh"},
            {"Repository not found", "Bitbucket"},
            {"Unrecognized domain", "Mashery"},
            {"This UserVoice subdomain is currently available", "UserVoice"},
            {"is not a registered InCloud YouTrack", "YouTrack"},
            {"The requested URL was not found on this server. That's all we know", "Google (GCP)"},
            {"Trying to access your account?", "Tilda"},
            {"nginx", "Possible dangling nginx default page"},
            {"It looks like you may have taken a wrong turn somewhere", "Ngrok"},
            {"Domain uses DO Spaces but the space does not exist", "DigitalOcean Spaces"},
            {"If you're the owner of this website", "Pantheon"},
            {"404 Blog is not found", "Ghost"},
            {"Uh oh. That page doesn't exist", "Intercom / Help Scout"},
            {"data-html-name=\"Anchor Not Found\"", "Cargo"},
            {"The gods are wise, but do not know of the site", "Tave"},
    };

    // ---- CORS: origin variants to probe (placeholders substituted at runtime) ----
    // {HOST} = target host, {APEX} = registrable apex. The tool substitutes and sends each as Origin.
    public static final String[] CORS_ORIGIN_TEMPLATES = {
            "https://evil-acme-probe.com",                 // arbitrary external origin
            "null",                                          // sandboxed/redirect origin
            "http://{HOST}",                                 // scheme downgrade
            "https://{HOST}.evil-acme-probe.com",            // target as subdomain of attacker
            "https://evil-acme-probe.com.{HOST}",            // attacker string as prefix (weak suffix match)
            "https://{HOST}evil.com",                        // missing-dot suffix bypass
            "https://not-real-sub.{APEX}",                   // trusted-but-unclaimed subdomain
    };

    // ---- Web cache poisoning: commonly-unkeyed headers ----
    public static final String[] UNKEYED_HEADERS = {
            "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
            "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "X-Original-URL", "X-Rewrite-URL",
            "X-Original-Host", "X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Cache-Key",
    };

    // ---- Host-header injection targets ----
    public static final String[] HOST_INJECT_HEADERS = {
            "Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override",
            "Forwarded",
    };

    // ---- Open-redirect payloads. {EVIL} = attacker host, {TARGET} = target host ----
    public static final String[] OPEN_REDIRECT_PAYLOADS = {
            "https://{EVIL}",
            "//{EVIL}",
            "/\\{EVIL}",
            "https:/{EVIL}",
            "https://{TARGET}.{EVIL}",
            "https://{EVIL}/?{TARGET}",
            "https://{EVIL}#{TARGET}",
            "https://{EVIL}%2f%2e%2e",
            "https://{TARGET}@{EVIL}",
            "/%2F{EVIL}",
            "/%5C%5C{EVIL}",
            "⁄⁄{EVIL}",  // unicode slash bypass
    };

    // ---- Hidden/unkeyed request headers worth brute-forcing (Param-Miner style) ----
    public static final String[] HEADER_WORDLIST = {
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Scheme",
            "X-Forwarded-Proto", "X-Real-IP", "X-Client-IP", "True-Client-IP", "X-Originating-IP",
            "CF-Connecting-IP", "X-Custom-IP-Authorization", "X-Forwarded-Server", "X-Host",
            "X-Remote-IP", "X-Remote-Addr", "X-Debug", "X-Debug-Mode", "X-Feature", "X-Feature-Flag",
            "X-Country-Code", "X-Wap-Profile", "X-Requested-With", "X-Override-URL", "X-HTTP-Method-Override",
            "X-Api-Version", "X-Amz-Cf-Id", "X-Timer", "X-Cache", "X-Backend", "X-Env", "X-Environment",
    };

    // ---- WAF fingerprints: header/body signature -> WAF name ----
    public static final String[][] WAF_SIGNATURES = {
            {"cloudflare", "Cloudflare"},
            {"Attention Required! | Cloudflare", "Cloudflare"},
            {"__cfduid", "Cloudflare"},
            {"cf-ray", "Cloudflare"},
            {"AkamaiGHost", "Akamai"},
            {"akamai", "Akamai"},
            {"Incapsula", "Imperva Incapsula"},
            {"_incap_", "Imperva Incapsula"},
            {"X-Iinfo", "Imperva Incapsula"},
            {"mod_security", "ModSecurity"},
            {"ModSecurity", "ModSecurity"},
            {"Sucuri", "Sucuri CloudProxy"},
            {"x-sucuri-id", "Sucuri CloudProxy"},
            {"Barracuda", "Barracuda"},
            {"BigIP", "F5 BIG-IP"},
            {"F5", "F5 BIG-IP"},
            {"The requested URL was rejected", "F5 BIG-IP ASM"},
            {"AWS WAF", "AWS WAF"},
            {"awselb", "AWS ELB/WAF"},
            {"FORTIWAFSID", "Fortinet FortiWeb"},
            {"Wangsu", "Wangsu / CDNetworks"},
            {"aesecure", "aeSecure"},
            {"NAXSI", "NAXSI"},
    };

    /** A benign-but-attacky string to trip a WAF for fingerprinting (no real payload effect). */
    public static final String WAF_TRIGGER = "?bbtest=<script>alert(1)</script>' OR '1'='1' UNION SELECT-- -";

    // ---- Prototype pollution probes ----
    public static final String[] PROTO_POLLUTION_URL = {
            "__proto__[bbpp]=polluted",
            "__proto__.bbpp=polluted",
            "constructor[prototype][bbpp]=polluted",
    };
    public static final String PROTO_POLLUTION_JSON = "{\"__proto__\":{\"bbpp\":\"polluted\"}}";
    public static final String PROTO_POLLUTION_MARKER = "bbpp";
    public static final String PROTO_POLLUTION_VALUE = "polluted";

    // ---- Cloud metadata endpoints for SSRF ----
    public static final String[] SSRF_METADATA = {
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    };
}
