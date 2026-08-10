package com.example.burpgemini.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Mines an HTML/JS response body for recon-relevant artifacts: links, script/asset URLs, API
 * endpoints, HTML/JS comments, forms, emails and likely secrets. Purely local (operates on content
 * already fetched); results are bounded and secret values are masked.
 */
public final class ContentExtractor {

    private ContentExtractor() {
    }

    private static final int CAP = 120;

    private static final Pattern HREF_SRC = Pattern.compile("(?:href|src|action)\\s*=\\s*[\"']([^\"'>\\s]+)[\"']",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern ABS_URL = Pattern.compile("https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+");
    private static final Pattern ENDPOINT = Pattern.compile("[\"'`](/(?:api|v\\d+|graphql|rest|internal|admin|auth|user|users|account|oauth)[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]*)[\"'`]");
    private static final Pattern HTML_COMMENT = Pattern.compile("<!--(.*?)-->", Pattern.DOTALL);
    private static final Pattern FORM = Pattern.compile("<form\\b([^>]*)>(.*?)</form>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern INPUT_NAME = Pattern.compile("name\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{3,}");
    private static final Pattern AWS = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern SECRET_ASSIGN = Pattern.compile(
            "(?i)(api[_-]?key|secret|token|access[_-]?token|client[_-]?secret|passwd|password|aws[_-]?secret)"
                    + "\"?\\s*[:=]\\s*[\"']([A-Za-z0-9_\\-./+]{8,})[\"']");

    /** Extract artifacts from {@code body}; {@code baseUrl} resolves relative links. */
    public static JsonObject extract(String body, String baseUrl) {
        JsonObject out = new JsonObject();
        if (body == null) {
            return out;
        }
        String scan = body.length() > 400_000 ? body.substring(0, 400_000) : body;

        Set<String> links = new LinkedHashSet<>();
        Set<String> scripts = new LinkedHashSet<>();
        Matcher m = HREF_SRC.matcher(scan);
        while (m.find() && links.size() + scripts.size() < CAP * 2) {
            String raw = m.group(1);
            String abs = resolve(baseUrl, raw);
            if (abs == null) {
                continue;
            }
            if (abs.toLowerCase().contains(".js")) {
                scripts.add(abs);
            } else {
                links.add(abs);
            }
        }
        m = ABS_URL.matcher(scan);
        while (m.find() && links.size() < CAP) {
            links.add(m.group());
        }

        Set<String> endpoints = new LinkedHashSet<>();
        m = ENDPOINT.matcher(scan);
        while (m.find() && endpoints.size() < CAP) {
            endpoints.add(m.group(1));
        }

        Set<String> comments = new LinkedHashSet<>();
        m = HTML_COMMENT.matcher(scan);
        while (m.find() && comments.size() < 40) {
            String c = m.group(1).trim().replaceAll("\\s+", " ");
            if (!c.isEmpty() && c.length() < 300) {
                comments.add(c);
            }
        }

        JsonArray forms = new JsonArray();
        m = FORM.matcher(scan);
        int fc = 0;
        while (m.find() && fc++ < 20) {
            JsonObject f = new JsonObject();
            String attrs = m.group(1);
            f.addProperty("action", attr(attrs, "action"));
            f.addProperty("method", attr(attrs, "method"));
            Set<String> inputs = new LinkedHashSet<>();
            Matcher im = INPUT_NAME.matcher(m.group(2));
            while (im.find() && inputs.size() < 30) {
                inputs.add(im.group(1));
            }
            f.add("inputs", toArr(inputs));
            forms.add(f);
        }

        Set<String> emails = new LinkedHashSet<>();
        m = EMAIL.matcher(scan);
        while (m.find() && emails.size() < 40) {
            emails.add(m.group());
        }

        Set<String> secrets = new LinkedHashSet<>();
        collect(JWT.matcher(scan), secrets, "JWT");
        collect(AWS.matcher(scan), secrets, "AWS key");
        m = SECRET_ASSIGN.matcher(scan);
        while (m.find() && secrets.size() < 40) {
            secrets.add(m.group(1) + " = " + mask(m.group(2)));
        }

        out.add("links", toArr(links));
        out.add("scripts", toArr(scripts));
        out.add("endpoints", toArr(endpoints));
        out.add("comments", toArr(comments));
        out.add("forms", forms);
        out.add("emails", toArr(emails));
        out.add("secrets", toArr(secrets));
        return out;
    }

    private static void collect(Matcher m, Set<String> into, String kind) {
        int n = 0;
        while (m.find() && n++ < 20) {
            into.add(kind + ": " + mask(m.group()));
        }
    }

    private static String resolve(String baseUrl, String raw) {
        if (raw == null || raw.isBlank() || raw.startsWith("data:") || raw.startsWith("javascript:")
                || raw.startsWith("#") || raw.startsWith("mailto:")) {
            return null;
        }
        try {
            if (raw.startsWith("http://") || raw.startsWith("https://")) {
                return raw;
            }
            if (baseUrl == null || baseUrl.isBlank()) {
                return raw;
            }
            return URI.create(baseUrl).resolve(raw).toString();
        } catch (RuntimeException e) {
            return raw;
        }
    }

    private static String attr(String attrs, String name) {
        Matcher m = Pattern.compile(name + "\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE).matcher(attrs);
        return m.find() ? m.group(1) : "";
    }

    private static JsonArray toArr(Set<String> set) {
        JsonArray a = new JsonArray();
        for (String s : set) {
            a.add(s);
        }
        return a;
    }

    private static String mask(String v) {
        if (v == null) {
            return "";
        }
        if (v.length() <= 12) {
            return v.charAt(0) + "***";
        }
        return v.substring(0, 6) + "…" + v.substring(v.length() - 4) + " (len " + v.length() + ")";
    }
}
