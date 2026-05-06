import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

export interface ChatMessage {
  role: 'user' | 'assistant';
  text: string;
  timestamp: Date;
  warnings?: string[];
}

export interface AgentResponse {
  question: string;
  answer: string;
  guardrail_warnings?: string[];
  processing_time_ms?: number;
}

export interface ApiError {
  detail: string;
  status: number;
}

@Injectable({ providedIn: 'root' })
export class ChatService {
  private readonly apiUrl = 'http://localhost:8000/ask';

  constructor(private http: HttpClient) {}

  ask(question: string): Observable<AgentResponse> {
    return this.http
      .post<AgentResponse>(this.apiUrl, { question })
      .pipe(catchError(this.handleError));
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    let message = 'An unexpected error occurred. Please try again.';

    if (error.status === 400) {
      // Guardrail block — FastAPI returns the reason in detail
      const detail = error.error?.detail || error.error;
      message = typeof detail === 'string' ? detail : 'Your request was blocked by the safety filter.';
    } else if (error.status === 429) {
      message = 'Too many requests. Please wait a moment before trying again.';
    } else if (error.status === 503) {
      message = 'The AI service is temporarily unavailable. Please try again later.';
    } else if (error.status === 0) {
      message = 'Could not connect to the server. Make sure the backend is running.';
    }

    return throwError(() => ({ detail: message, status: error.status } as ApiError));
  }
}