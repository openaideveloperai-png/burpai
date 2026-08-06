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
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.util.List;

/**
 * "AI Recon" suite tab: a live view of everything the background {@link PassiveScanner} has
 * collected — the deduplicated findings and the endpoint inventory. Read-only, auto-refreshing.
 */
public final class ReconTab extends JPanel {

    private final FindingsStore store;
    private ChatController controller;

    private final JLabel summary = new JLabel();
    private final DefaultTableModel findingsModel = new DefaultTableModel(
            new Object[]{"Severity", "Type", "URL", "Evidence", "Src"}, 0) {
        @Override
        public boolean isCellEditable(int r, int c) {
            return false;
        }
    };
    private final DefaultTableModel endpointsModel = new DefaultTableModel(
            new Object[]{"URL", "Methods", "Statuses", "Hits"}, 0) {
        @Override
        public boolean isCellEditable(int r, int c) {
            return false;
        }
    };
    private final Timer refreshTimer;

    public ReconTab(FindingsStore store) {
        this.store = store;
        setLayout(new BorderLayout());

        add(buildToolbar(), BorderLayout.NORTH);

        JTable findingsTable = new JTable(findingsModel);
        findingsTable.setAutoCreateRowSorter(true);
        findingsTable.getColumnModel().getColumn(0).setMaxWidth(90);
        findingsTable.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
        findingsTable.getColumnModel().getColumn(4).setMaxWidth(80);

        JTable endpointsTable = new JTable(endpointsModel);
        endpointsTable.setAutoCreateRowSorter(true);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings", new JScrollPane(findingsTable));
        tabs.addTab("Endpoints", new JScrollPane(endpointsTable));
        add(tabs, BorderLayout.CENTER);

        // Coalesce bursts of proxy activity into one refresh.
        refreshTimer = new Timer(400, e -> refresh());
        refreshTimer.setRepeats(false);
        store.setListener(() -> SwingUtilities.invokeLater(refreshTimer::restart));

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
        analyze.setToolTipText("Ask the AI Assistant to prioritise these findings and suggest next steps.");
        analyze.addActionListener(e -> {
            if (controller != null) {
                controller.submitUserMessage(
                        "Review the passive recon collected so far by calling get_passive_findings, "
                        + "then give me a prioritised summary of the most important findings with "
                        + "severity and concrete next steps (least-intrusive tests first).");
            }
        });
        JButton clear = new JButton("Clear");
        clear.addActionListener(e -> store.clear());

        bar.add(analyze);
        bar.add(Box.createHorizontalStrut(6));
        bar.add(clear);
        return bar;
    }

    private void refresh() {
        List<PassiveFinding> fs = store.findingsSnapshot();
        findingsModel.setRowCount(0);
        for (PassiveFinding f : fs) {
            findingsModel.addRow(new Object[]{f.severity, f.type, f.url, f.evidence, f.ai ? "AI" : "auto"});
        }
        List<FindingsStore.EndpointInfo> eps = store.endpointsSnapshot();
        endpointsModel.setRowCount(0);
        for (FindingsStore.EndpointInfo e : eps) {
            endpointsModel.addRow(new Object[]{
                    e.sampleUrl, String.join(",", e.methods), joinInts(e.statuses), e.hits.get()});
        }
        summary.setText("Endpoints: " + store.endpointCount() + "   ·   Findings: " + store.findingCount()
                + "   (passive, read-only — records in-scope proxy traffic)");
    }

    private static String joinInts(java.util.Collection<Integer> c) {
        StringBuilder sb = new StringBuilder();
        for (Integer i : c) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(i);
        }
        return sb.toString();
    }

    /** Colour the severity cell so High/Medium stand out in both themes. */
    private static final class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
            String s = String.valueOf(value);
            Color fg;
            switch (s) {
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
