package com.example.burpgemini.ai;

import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Provider-neutral conversation model. The chat controller keeps history in these types; each
 * {@link AiProvider} translates them to/from its own wire format (Gemini contents, OpenAI messages,
 * …). This is what lets the same agent loop drive different backends behind a switch.
 */
public final class Neutral {

    private Neutral() {
    }

    public enum Role {USER, MODEL, TOOL}

    /** A declared tool (name + description + JSON-Schema parameters), independent of any provider. */
    public static final class ToolSpec {
        public final String name;
        public final String description;
        public final JsonObject parameters;

        public ToolSpec(String name, String description, JsonObject parameters) {
            this.name = name;
            this.description = description;
            this.parameters = parameters;
        }
    }

    /** A tool call requested by the model. */
    public static final class ToolCallRequest {
        public String id;          // OpenAI tool_call id; may be null for Gemini
        public String name;
        public JsonObject args;
        public String signature;   // Gemini thoughtSignature, preserved for round-trip; null otherwise

        public ToolCallRequest() {
        }

        public ToolCallRequest(String id, String name, JsonObject args, String signature) {
            this.id = id;
            this.name = name;
            this.args = args;
            this.signature = signature;
        }
    }

    /** The result of executing one tool call, fed back to the model. */
    public static final class ToolResult {
        public String id;          // must match the originating ToolCallRequest.id for OpenAI
        public String name;
        public JsonObject response;

        public ToolResult(String id, String name, JsonObject response) {
            this.id = id;
            this.name = name;
            this.response = response;
        }
    }

    /** One message in the conversation. */
    public static final class ChatMessage {
        public Role role;
        public String text;                       // user/model text (nullable)
        public List<ToolCallRequest> toolCalls;   // model turn requesting tools (nullable)
        public List<ToolResult> toolResults;      // tool turn carrying results (nullable)

        public static ChatMessage user(String text) {
            ChatMessage m = new ChatMessage();
            m.role = Role.USER;
            m.text = text;
            return m;
        }

        public static ChatMessage model(String text, List<ToolCallRequest> toolCalls) {
            ChatMessage m = new ChatMessage();
            m.role = Role.MODEL;
            m.text = text;
            m.toolCalls = toolCalls;
            return m;
        }

        public static ChatMessage toolResults(List<ToolResult> results) {
            ChatMessage m = new ChatMessage();
            m.role = Role.TOOL;
            m.toolResults = results;
            return m;
        }

        public boolean hasToolCalls() {
            return toolCalls != null && !toolCalls.isEmpty();
        }
    }

    /** The outcome of one model turn. */
    public static final class TurnResult {
        public boolean ok;
        public boolean cancelled;
        public String errorMessage;
        public int httpStatus;
        public String blockReason;

        public String text = "";
        public List<ToolCallRequest> toolCalls = new ArrayList<>();
        /** The model message to append to history (role MODEL). */
        public ChatMessage modelMessage;

        public static TurnResult error(String msg, int status) {
            TurnResult r = new TurnResult();
            r.ok = false;
            r.errorMessage = msg;
            r.httpStatus = status;
            return r;
        }

        public static TurnResult cancelled() {
            TurnResult r = new TurnResult();
            r.ok = false;
            r.cancelled = true;
            r.errorMessage = "Cancelled.";
            return r;
        }
    }
}
