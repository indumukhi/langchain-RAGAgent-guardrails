package com.example.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record QuestionRequest(
        @NotBlank(message = "question must not be blank")
        @Size(min = 3, max = 2000, message = "question must be between 3 and 2000 characters")
        String question
) {}