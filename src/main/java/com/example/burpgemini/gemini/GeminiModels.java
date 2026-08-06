package com.example.burpgemini.gemini;

import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Data-transfer objects for the Gemini {@code generateContent} REST API.
 *
 * <p>Gson serialises these directly; null fields are omitted by default, so a {@link Part} carrying
 * only {@code text} will not emit an empty {@code functionCall}, and vice-versa.
 */
public final class GeminiModels {

    private GeminiModels() {
    }

    // ---- request -----------------------------------------------------------

    public static final class GenerateContentRequest {
        public SystemInstruction systemInstruction;
        public List<Content> contents = new ArrayList<>();
        public List<Tool> tools;
        public GenerationConfig generationConfig;
    }

    public static final class SystemInstruction {
        public List<Part> parts = new ArrayList<>();

        public static SystemInstruction of(String text) {
            SystemInstruction si = new SystemInstruction();
            si.parts.add(Part.text(text));
            return si;
        }
    }

    public static final class GenerationConfig {
        // The live Gemini API configures reasoning depth via generationConfig.thinkingConfig
        // (thinkingBudget), not a top-level "thinking_level" field.
        public ThinkingConfig thinkingConfig;

        public static GenerationConfig thinking(String level) {
            GenerationConfig g = new GenerationConfig();
            g.thinkingConfig = ThinkingConfig.forLevel(level);
            return g;
        }
    }

    public static final class ThinkingConfig {
        /** Token budget for internal reasoning: -1 = dynamic (deep), 0 = minimal/off. */
        public Integer thinkingBudget;

        static ThinkingConfig forLevel(String level) {
            ThinkingConfig t = new ThinkingConfig();
            t.thinkingBudget = "low".equalsIgnoreCase(level) ? 0 : -1;
            return t;
        }
    }

    public static final class Content {
        public String role; // "user" or "model"
        public List<Part> parts = new ArrayList<>();

        public Content() {
        }

        public Content(String role, List<Part> parts) {
            this.role = role;
            this.parts = parts;
        }

        public static Content userText(String text) {
            Content c = new Content();
            c.role = "user";
            c.parts.add(Part.text(text));
            return c;
        }
    }

    public static final class Part {
        public String text;
        public FunctionCall functionCall;
        public FunctionResponse functionResponse;
        // Gemini 3 thinking models attach a thoughtSignature to functionCall (and some text) parts.
        // It MUST be echoed back verbatim when the part is resent, or tool calls fail with HTTP 400.
        public String thoughtSignature;

        public static Part text(String t) {
            Part p = new Part();
            p.text = t;
            return p;
        }

        public static Part functionResponse(String name, JsonObject response) {
            Part p = new Part();
            p.functionResponse = new FunctionResponse(name, response);
            return p;
        }
    }

    public static final class FunctionCall {
        public String name;
        public JsonObject args;
    }

    public static final class FunctionResponse {
        public String name;
        public JsonObject response;

        public FunctionResponse(String name, JsonObject response) {
            this.name = name;
            this.response = response;
        }
    }

    // ---- tool declarations -------------------------------------------------

    public static final class Tool {
        public List<FunctionDeclaration> functionDeclarations = new ArrayList<>();
    }

    public static final class FunctionDeclaration {
        public String name;
        public String description;
        public JsonObject parameters; // JSON-Schema (OpenAPI subset)

        public FunctionDeclaration(String name, String description, JsonObject parameters) {
            this.name = name;
            this.description = description;
            this.parameters = parameters;
        }
    }

    // ---- response ----------------------------------------------------------

    public static final class GenerateContentResponse {
        public List<Candidate> candidates;
        public PromptFeedback promptFeedback;
        public ApiError error;
    }

    public static final class Candidate {
        public Content content;
        public String finishReason;
    }

    public static final class PromptFeedback {
        public String blockReason;
    }

    public static final class ApiError {
        public int code;
        public String message;
        public String status;
    }
}
