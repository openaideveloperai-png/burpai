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
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> {
            store.clear();
            info.clear();
        });
        bar.add(analyze);
        bar.add(Box.createHorizontalStrut(6));
        bar.add(clear);
        return bar;
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
