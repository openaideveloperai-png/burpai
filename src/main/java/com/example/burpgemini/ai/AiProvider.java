package com.example.burpgemini.ai;

import com.example.burpgemini.ai.Neutral.ChatMessage;
import com.example.burpgemini.ai.Neutral.ToolSpec;
import com.example.burpgemini.ai.Neutral.TurnResult;

import java.util.List;

/**
 * A pluggable AI backend. Implementations translate the neutral conversation into their own wire
 * format, call their API, and translate the reply back. The chat controller depends only on this
 * interface, so switching provider is a matter of selecting a different implementation.
 */
public interface AiProvider {

    /** Stable id used in settings, e.g. "gemini" or "puter". */
    String id();

    /** Human-readable name for the UI. */
    String displayName();

    /** True when the provider has the credentials it needs (key/token). */
    boolean isConfigured();

    /** Short reason shown when {@link #isConfigured()} is false. */
    String notConfiguredHint();

    /** Run one model turn over the full neutral history + declared tools. */
    TurnResult sendTurn(String systemPrompt, List<ChatMessage> history, List<ToolSpec> tools);

    /** A tiny ping used by the Config tab's "Test connection". */
    TurnResult testConnection();

    /** Cancel any in-flight HTTP call. */
    void cancelInFlight();
}
