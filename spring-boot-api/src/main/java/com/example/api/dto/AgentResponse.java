package com.example.api.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AgentResponse(
        String question,
        String answer,
        @JsonProperty("guardrail_warnings") List<String> guardrailWarnings,
        @JsonProperty("processing_time_ms") Double processingTimeMs
) {}