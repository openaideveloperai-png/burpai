package com.example.burpgemini.util;

import java.util.ArrayList;
import java.util.List;

/**
 * Minimal line-level diff (LCS-based) used to show the operator exactly how an outgoing request
 * differs from its base in the confirmation card. Requests are small, so O(n·m) is fine.
 */
public final class TextDiff {

    private TextDiff() {
    }

    /** Produce a compact unified-style diff: {@code -} removed, {@code +} added, space unchanged. */
    public static String unified(String before, String after) {
        String[] a = before.split("\n", -1);
        String[] b = after.split("\n", -1);
        int n = a.length;
        int m = b.length;

        int[][] lcs = new int[n + 1][m + 1];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                if (a[i].equals(b[j])) {
                    lcs[i][j] = lcs[i + 1][j + 1] + 1;
                } else {
                    lcs[i][j] = Math.max(lcs[i + 1][j], lcs[i][j + 1]);
                }
            }
        }

        List<String> out = new ArrayList<>();
        int i = 0;
        int j = 0;
        while (i < n && j < m) {
            if (a[i].equals(b[j])) {
                out.add("  " + a[i]);
                i++;
                j++;
            } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
                out.add("- " + a[i]);
                i++;
            } else {
                out.add("+ " + b[j]);
                j++;
            }
        }
        while (i < n) {
            out.add("- " + a[i++]);
        }
        while (j < m) {
            out.add("+ " + b[j++]);
        }

        // Collapse long runs of unchanged context to keep the card readable.
        return collapseContext(out, 2);
    }

    private static String collapseContext(List<String> lines, int context) {
        boolean[] keep = new boolean[lines.size()];
        for (int k = 0; k < lines.size(); k++) {
            if (lines.get(k).startsWith("- ") || lines.get(k).startsWith("+ ")) {
                for (int c = Math.max(0, k - context); c <= Math.min(lines.size() - 1, k + context); c++) {
                    keep[c] = true;
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        boolean gapShown = false;
        for (int k = 0; k < lines.size(); k++) {
            if (keep[k]) {
                sb.append(lines.get(k)).append('\n');
                gapShown = false;
            } else if (!gapShown) {
                sb.append("  …\n");
                gapShown = true;
            }
        }
        String s = sb.toString();
        return s.isBlank() ? "(no differences)" : s.stripTrailing();
    }
}
