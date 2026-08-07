package com.example.burpgemini;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.example.burpgemini.ai.AiProvider;
import com.example.burpgemini.ai.GeminiProvider;
import com.example.burpgemini.ai.ModelsCatalog;
import com.example.burpgemini.ai.OpenAiCompatibleProvider;
import com.example.burpgemini.chat.ChatController;
import com.example.burpgemini.chat.ChatTab;
import com.example.burpgemini.config.ConfigTab;
import com.example.burpgemini.config.Settings;
import com.example.burpgemini.recon.AiEnricher;
import com.example.burpgemini.recon.FindingsStore;
import com.example.burpgemini.recon.InfoStore;
import com.example.burpgemini.recon.PassiveScanner;
import com.example.burpgemini.recon.ReconTab;
import com.example.burpgemini.safety.ConfirmationManager;
import com.example.burpgemini.safety.ScopeGuard;
import com.example.burpgemini.tools.ToolExecutor;
import com.example.burpgemini.tools.ToolRegistry;
import com.example.burpgemini.util.BurpContext;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Extension entry point.
 *
 * <p>Wires the whole assistant together: settings + Gemini client + tool registry/executor + the
 * safety layer (scope guard, confirmation gate) + the Config and Chat tabs, then registers the
 * "Send to AI Assistant" context-menu action and a clean unloading handler.
 *
 * <p>Uses the default {@code enhancedCapabilities()} (none) — no special capability is required.
 */
public final class BurpGeminiExtension implements BurpExtension {

    private BurpContext ctx;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AI Assistant (Gemini / Puter)");

        // Core wiring.
        Settings settings = new Settings(api);
        this.ctx = new BurpContext(api, settings);

        ToolRegistry registry = new ToolRegistry();

        // Background passive recon.
        FindingsStore findings = new FindingsStore();
        InfoStore info = new InfoStore();
        ToolExecutor executor = new ToolExecutor(ctx, findings, info);
        ScopeGuard scopeGuard = new ScopeGuard(api, settings);
        ConfirmationManager confirmations = new ConfirmationManager(settings);

        PassiveScanner scanner = new PassiveScanner(ctx, findings, info);
        AiEnricher enricher = new AiEnricher(ctx, findings);
        scanner.setEnricher(enricher);
        enricher.start();
        api.proxy().registerResponseHandler(scanner);

        // AI providers (switchable). First entry is the default.
        List<AiProvider> providers = List.of(
                new GeminiProvider(ctx),
                new OpenAiCompatibleProvider(ctx));

        // UI + controller.
        ChatTab chatTab = new ChatTab(ctx, settings);
        ChatController controller = new ChatController(
                ctx, settings, providers, executor, confirmations, scopeGuard, registry, chatTab);
        chatTab.setController(controller);

        ReconTab reconTab = new ReconTab(findings, info);
        reconTab.setController(controller);

        ModelsCatalog catalog = new ModelsCatalog();
        ConfigTab configTab = new ConfigTab(ctx, settings, providers, catalog);
        configTab.setChatTab(chatTab);

        // Register suite tabs.
        api.userInterface().registerSuiteTab("AI Assistant", chatTab);
        api.userInterface().registerSuiteTab("AI Recon", reconTab);
        api.userInterface().registerSuiteTab("AI Assistant Config", configTab);

        // "Send to AI Assistant" context menu across Proxy/Repeater/Target/Intruder/browser.
        api.userInterface().registerContextMenuItemsProvider(new SendToAssistantMenu());

        // Clean shutdown: cancel work + stop the thread pool on unload.
        api.extension().registerUnloadingHandler(() -> {
            try {
                controller.cancelCurrentTurn();
                enricher.stop();
            } finally {
                ctx.shutdown();
            }
            api.logging().logToOutput("AI Assistant unloaded; background work stopped.");
        });

        ctx.logInfo("AI Assistant loaded. Pick a provider and set its key/token in the "
                + "'AI Assistant Config' tab. For authorized, in-scope testing only.");
    }

    /** Provides the right-click action that attaches selected requests to the chat as context. */
    private final class SendToAssistantMenu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> selected = collect(event);
            if (selected.isEmpty()) {
                return List.of();
            }
            JMenuItem item = new JMenuItem(selected.size() == 1
                    ? "Send to AI Assistant"
                    : "Send " + selected.size() + " requests to AI Assistant");
            item.addActionListener(e -> {
                ctx.setContextItems(selected);
                ctx.logInfo("Attached " + selected.size() + " item(s) to the AI Assistant as context. "
                        + "Open the 'AI Assistant' tab to ask about them.");
            });
            return List.of(item);
        }

        private List<HttpRequestResponse> collect(ContextMenuEvent event) {
            List<HttpRequestResponse> out = new ArrayList<>(event.selectedRequestResponses());
            if (out.isEmpty()) {
                event.messageEditorRequestResponse().ifPresent(m -> out.add(m.requestResponse()));
            }
            return out;
        }
    }
}
