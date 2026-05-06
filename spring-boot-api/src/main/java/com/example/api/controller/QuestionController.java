package com.example.api.controller;

import com.example.api.dto.AgentResponse;
import com.example.api.dto.QuestionRequest;
import com.example.api.service.AgentService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200")
public class QuestionController {

    private final AgentService agentService;

    public QuestionController(AgentService agentService) {
        this.agentService = agentService;
    }

    @PostMapping("/ask")
    public ResponseEntity<AgentResponse> ask(@Valid @RequestBody QuestionRequest request) {
        AgentResponse response = agentService.ask(request.question());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }
}