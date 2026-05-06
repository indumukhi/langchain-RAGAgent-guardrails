package com.example.api.service;

import com.example.api.dto.AgentResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@Service
public class AgentService {

    private static final Logger log = LoggerFactory.getLogger(AgentService.class);

    private final RestClient restClient;

    public AgentService(@Value("${agent.fastapi-url}") String fastapiUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(fastapiUrl)
                .defaultHeader("Content-Type", "application/json")
                .build();
    }

    public AgentResponse ask(String question) {
        log.info("Forwarding question to FastAPI agent (length={})", question.length());

        try {
            AgentResponse response = restClient.post()
                    .uri("/ask")
                    .body(Map.of("question", question))
                    .retrieve()
                    .body(AgentResponse.class);

            if (response != null && response.guardrailWarnings() != null && !response.guardrailWarnings().isEmpty()) {
                log.warn("Guardrail warnings for question: {}", response.guardrailWarnings());
            }
            log.info("Received answer in {}ms", response != null ? response.processingTimeMs() : "?");
            return response;

        } catch (HttpClientErrorException ex) {
            // 400 = guardrail block, 429 = rate limit — propagate status + message
            log.warn("FastAPI returned {} for question: {}", ex.getStatusCode(), ex.getMessage());
            throw new ResponseStatusException(ex.getStatusCode(), ex.getResponseBodyAsString());
        } catch (HttpServerErrorException ex) {
            log.error("FastAPI 5xx error: {}", ex.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "AI service error. Please try again later.");
        } catch (Exception ex) {
            log.error("Failed to reach FastAPI agent", ex);
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "AI service is unreachable.");
        }
    }
}