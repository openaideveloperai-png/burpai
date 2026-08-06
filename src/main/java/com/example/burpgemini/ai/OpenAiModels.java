package com.example.burpgemini.ai;

import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * DTOs for the OpenAI Chat Completions wire format, used by the Puter backend (and any other
 * OpenAI-compatible endpoint). Gson omits null fields, so optional keys are simply left unset.
 */
final class OpenAiModels {

    private OpenAiModels() {
    }

    // ---- request -----------------------------------------------------------

    static final class ChatRequest {
        String model;
        List<Message> messages = new ArrayList<>();
        List<ToolDef> tools;
        String tool_choice; // "auto"
    }

    static final class Message {
        String role;                 // system | user | assistant | tool
        String content;              // text (or JSON string for tool results)
        List<ToolCall> tool_calls;   // assistant turn requesting tools
        String tool_call_id;         // tool turn: which call this answers

        static Message of(String role, String content) {
            Message m = new Message();
            m.role = role;
            m.content = content;
            return m;
        }
    }

    static final class ToolDef {
        String type = "function";
        FunctionDef function; // null for built-in/hosted tools like web_search

        ToolDef(FunctionDef function) {
            this.function = function;
        }

        /** A built-in/hosted tool such as {@code web_search} (no function schema). */
        ToolDef(String type) {
            this.type = type;
            this.function = null;
        }
    }

    static final class FunctionDef {
        String name;
        String description;
        JsonObject parameters;

        FunctionDef(String name, String description, JsonObject parameters) {
            this.name = name;
            this.description = description;
            this.parameters = parameters;
        }
    }

    static final class ToolCall {
        String id;
        String type = "function";
        FunctionCall function;
    }

    static final class FunctionCall {
        String name;
        String arguments; // a JSON string, per the OpenAI spec
    }

    // ---- response ----------------------------------------------------------

    static final class ChatResponse {
        List<Choice> choices;
        ApiError error;
    }

    static final class Choice {
        Message message;
        String finish_reason;
    }

    static final class ApiError {
        String message;
        String type;
        String code;
    }
}
