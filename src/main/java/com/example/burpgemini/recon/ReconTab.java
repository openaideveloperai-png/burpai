package com.example.burpgemini.recon;

import com.example.burpgemini.chat.ChatController;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.util.Collection;
import java.util.List;

/**
 * "AI Recon" suite tab: a live, read-only view of what the background scanner has collected —
 * findings, the endpoint inventory, and the information-gathering aggregates (parameters, secrets,
 * headers/cookies/tech/hosts). Auto-refreshing.
 */
public final class ReconTab extends JPanel {

    private final FindingsStore store;
    private final InfoStore info;
    private ChatController controller;

    private final JLabel summary = new JLabel();

    private final DefaultTableModel findingsModel = ro(new Object[]{"Severity", "×", "Type", "URL", "Evidence", "Src"});
    private final DefaultTableModel endpointsModel = ro(new Object[]{"URL", "Methods", "Statuses", "Hits"});
    private final DefaultTableModel paramsModel = ro(new Object[]{"Parameter", "Types", "Sample values", "#Endpoints", "Hits"});
    private final DefaultTableModel secretsModel = ro(new Object[]{"Kind", "Value (masked)", "#Seen", "Sample URL"});
    private final JTextArea infoArea = new JTextArea();

    private final Timer refreshTimer;

    public ReconTab(FindingsStore store, InfoStore info) {
        this.store = store;
        this.info = info;
        setLayout(new BorderLayout());
        add(buildToolbar(), BorderLayout.NORTH);

        JTable findingsTable = new JTable(findingsModel);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.getColumnModel().getColumn(0).setMaxWidth(90);
        findingsTable.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
        findingsTable.getColumnModel().getColumn(1).setMaxWidth(48);
        findingsTable.getColumnModel().getColumn(5).setMaxWidth(70);

        JTable endpointsTable = new JTable(endpointsModel);
        endpointsTable.setAutoCreateRowSorter(true);
        JTable paramsTable = new JTable(paramsModel);
        paramsTable.setAutoCreateRowSorter(true);
        JTable secretsTable = new JTable(secretsModel);
        secretsTable.setAutoCreateRowSorter(true);

        infoArea.setEditable(false);
        infoArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings", new JScrollPane(findingsTable));
        tabs.addTab("Endpoints", new JScrollPane(endpointsTable));
        tabs.addTab("Parameters", new JScrollPane(paramsTable));
        tabs.addTab("Secrets / Tokens", new JScrollPane(secretsTable));
        tabs.addTab("Headers / Tech / Hosts", new JScrollPane(infoArea));
        add(tabs, BorderLayout.CENTER);

        refreshTimer = new Timer(400, e -> refresh());
        refreshTimer.setRepeats(false);
        Runnable trigger = () -> SwingUtilities.invokeLater(refreshTimer::restart);
        store.setListener(trigger);
        info.setListener(trigger);

        refresh();
    }

    public void setController(ChatController controller) {
        this.controller = controller;
    }

    private JComponent buildToolbar() {
        JPanel bar = new JPanel();
        bar.setLayout(new BoxLayout(bar, BoxLayout.X_AXIS));
        bar.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        bar.add(summary);
        bar.add(Box.createHorizontalGlue());

        JButton analyze = new JButton("Analyze in chat");
        analyze.setToolTipText("Ask the AI Assistant to prioritise this recon and suggest next steps.");
        analyze.addActionListener(e -> {
            if (controller != null) {
                controller.submitUserMessage(
                        "Review the background recon by calling get_recon_data and get_passive_findings, "
                        + "then give me a prioritised summary: the most interesting parameters and "
                        + "endpoints to test, any exposed secrets/tokens, and concrete next steps "
                        + "(least-intrusive tests first).");
            }
        });
        JButton export = new JButton("Export report");
        export.setToolTipText("Save the collected findings + recon as a Markdown report.");
        export.addActionListener(e -> exportReport());

        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> {
            store.clear();
            info.clear();
        });
        bar.add(analyze);
        bar.add(Box.createHorizontalStrut(6));
        bar.add(export);
        bar.add(Box.createHorizontalStrut(6));
        bar.add(clear);
        return bar;
    }

    private void exportReport() {
        javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
        chooser.setDialogTitle("Export recon report (Markdown)");
        chooser.setSelectedFile(new java.io.File("burp-ai-recon-report.md"));
        if (chooser.showSaveDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File file = chooser.getSelectedFile();
        try {
            java.nio.file.Files.writeString(file.toPath(), buildMarkdown());
            summary.setText("Report saved to " + file.getAbsolutePath());
        } catch (java.io.IOException ex) {
            javax.swing.JOptionPane.showMessageDialog(this, "Could not write report:\n" + ex.getMessage(),
                    "Export failed", javax.swing.JOptionPane.ERROR_MESSAGE);
        }
    }

    private String buildMarkdown() {
        StringBuilder md = new StringBuilder();
        md.append("# Burp AI Assistant — Recon Report\n\n");
        md.append("_Generated: ").append(java.time.ZonedDateTime.now()).append("_\n\n");
        md.append("## Summary\n\n");
        md.append("- Endpoints: ").append(store.endpointCount()).append('\n');
        md.append("- Findings: ").append(store.findingCount()).append('\n');
        md.append("- Parameters: ").append(info.paramCount()).append('\n');
        md.append("- Secrets/tokens: ").append(info.secretCount()).append("\n\n");

        md.append("## Findings\n\n");
        md.append("| Severity | Count | Type | URL | Evidence |\n|---|---|---|---|---|\n");
        for (PassiveFinding f : store.findingsSnapshot()) {
            md.append("| ").append(f.severity).append(" | ").append(f.occurrences).append(" | ")
              .append(cell(f.type)).append(" | ").append(cell(f.url)).append(" | ")
              .append(cell(f.evidence)).append(" |\n");
        }

        md.append("\n## Endpoints\n\n| URL | Methods | Statuses | Hits |\n|---|---|---|---|\n");
        for (FindingsStore.EndpointInfo e : store.endpointsSnapshot()) {
            md.append("| ").append(cell(e.sampleUrl)).append(" | ").append(String.join(",", e.methods))
              .append(" | ").append(join(e.statuses)).append(" | ").append(e.hits.get()).append(" |\n");
        }

        md.append("\n## Parameters\n\n| Name | Types | Sample values | #Endpoints | Hits |\n|---|---|---|---|---|\n");
        for (InfoStore.Param p : info.paramsSnapshot()) {
            md.append("| ").append(cell(p.name)).append(" | ").append(String.join(",", p.types))
              .append(" | ").append(cell(String.join(" \u007c ", p.samples))).append(" | ")
              .append(p.endpoints.size()).append(" | ").append(p.count.get()).append(" |\n");
        }

        md.append("\n## Secrets / Tokens (masked)\n\n| Kind | Value | #Seen | Sample URL |\n|---|---|---|---|\n");
        for (InfoStore.Secret s : info.secretsSnapshot()) {
            String url = s.urls.isEmpty() ? "" : s.urls.iterator().next();
            md.append("| ").append(cell(s.kind)).append(" | ").append(cell(s.masked)).append(" | ")
              .append(s.urls.size()).append(" | ").append(cell(url)).append(" |\n");
        }

        md.append("\n## Technologies\n\n");
        for (String t : info.technologies()) {
            md.append("- ").append(t).append('\n');
        }
        md.append("\n## Hosts\n\n");
        for (String h : info.hosts()) {
            md.append("- ").append(h).append('\n');
        }
        md.append("\n---\n_For authorized, in-scope testing only._\n");
        return md.toString();
    }

    /** Escape a value for a Markdown table cell. */
    private static String cell(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("|", "\\|").replace("\n", " ").replace("\r", " ");
    }

    private void refresh() {
        // Findings
        findingsModel.setRowCount(0);
        for (PassiveFinding f : store.findingsSnapshot()) {
            findingsModel.addRow(new Object[]{f.severity, f.occurrences, f.type, f.url, f.evidence, f.ai ? "AI" : "auto"});
        }
        // Endpoints
        endpointsModel.setRowCount(0);
        for (FindingsStore.EndpointInfo e : store.endpointsSnapshot()) {
            endpointsModel.addRow(new Object[]{
                    e.sampleUrl, String.join(",", e.methods), join(e.statuses), e.hits.get()});
        }
        // Parameters
        paramsModel.setRowCount(0);
        for (InfoStore.Param p : info.paramsSnapshot()) {
            paramsModel.addRow(new Object[]{
                    p.name, String.join(",", p.types), String.join(" | ", p.samples),
                    p.endpoints.size(), p.count.get()});
        }
        // Secrets
        secretsModel.setRowCount(0);
        for (InfoStore.Secret s : info.secretsSnapshot()) {
            String url = s.urls.isEmpty() ? "" : s.urls.iterator().next();
            secretsModel.addRow(new Object[]{s.kind, s.masked, s.urls.size(), url});
        }
        // Info summary
        infoArea.setText(buildInfoText());
        infoArea.setCaretPosition(0);

        summary.setText("Endpoints: " + store.endpointCount()
                + "   ·   Findings: " + store.findingCount()
                + "   ·   Params: " + info.paramCount()
                + "   ·   Secrets: " + info.secretCount()
                + "   (passive, read-only — records in-scope proxy traffic)");
    }

    private String buildInfoText() {
        StringBuilder sb = new StringBuilder();
        sb.append("TECHNOLOGIES\n");
        for (String t : info.technologies()) {
            sb.append("  ").append(t).append('\n');
        }
        sb.append("\nHOSTS (").append(info.hosts().size()).append(")\n");
        int n = 0;
        for (String h : info.hosts()) {
            if (n++ >= 100) {
                sb.append("  …\n");
                break;
            }
            sb.append("  ").append(h).append('\n');
        }
        sb.append("\nREQUEST HEADERS (name × count)\n");
        appendStats(sb, info.reqHeadersSnapshot());
        sb.append("\nRESPONSE HEADERS (name × count)\n");
        appendStats(sb, info.respHeadersSnapshot());
        sb.append("\nCOOKIES\n");
        appendStats(sb, info.cookiesSnapshot());
        sb.append("\nEMAILS (").append(info.emails().size()).append(")\n");
        n = 0;
        for (String e : info.emails()) {
            if (n++ >= 100) {
                sb.append("  …\n");
                break;
            }
            sb.append("  ").append(e).append('\n');
        }
        return sb.toString();
    }

    private static void appendStats(StringBuilder sb, List<InfoStore.NameStat> stats) {
        int n = 0;
        for (InfoStore.NameStat s : stats) {
            if (n++ >= 80) {
                sb.append("  …\n");
                break;
            }
            sb.append("  ").append(s.name).append(" ×").append(s.count.get());
            if (!s.samples.isEmpty()) {
                sb.append("   e.g. ").append(String.join(" | ", s.samples));
            }
            sb.append('\n');
        }
    }

    private static String join(Collection<Integer> c) {
        StringBuilder sb = new StringBuilder();
        for (Integer i : c) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(i);
        }
        return sb.toString();
    }

    private static DefaultTableModel ro(Object[] cols) {
        return new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
    }

    private static final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
            Color fg;
            switch (String.valueOf(value)) {
                case "High":
                    fg = new Color(0xD32F2F);
                    break;
                case "Medium":
                    fg = new Color(0xE65100);
                    break;
                case "Low":
                    fg = new Color(0xB59A00);
                    break;
                default:
                    fg = t.getForeground();
            }
            if (!sel) {
                c.setForeground(fg);
            }
            return c;
        }
    }
}
