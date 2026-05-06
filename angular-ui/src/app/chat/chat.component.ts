import { Component, ElementRef, ViewChild, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ChatService, ChatMessage, AgentResponse, ApiError } from '../services/chat.service';

@Component({
  selector: 'app-chat',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './chat.component.html',
  styleUrls: ['./chat.component.scss'],
})
export class ChatComponent {
  @ViewChild('messageList') private messageList!: ElementRef;

  messages: ChatMessage[] = [];
  userInput = '';
  loading = false;
  errorMessage = '';

  constructor(private chatService: ChatService, private cdr: ChangeDetectorRef) {}

  send(): void {
    const question = this.userInput.trim();
    if (!question || this.loading) return;

    this.messages.push({ role: 'user', text: question, timestamp: new Date() });
    this.userInput = '';
    this.loading = true;
    this.errorMessage = '';
    this.scrollToBottom();

    this.chatService.ask(question).subscribe({
      next: (res: AgentResponse) => {
        this.messages.push({
          role: 'assistant',
          text: res.answer,
          timestamp: new Date(),
          warnings: res.guardrail_warnings ?? [],
        });
        this.loading = false;
        this.cdr.detectChanges();
        this.scrollToBottom();
      },
      error: (err: ApiError) => {
        this.errorMessage = err.detail ?? 'Something went wrong. Please try again.';
        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  onEnter(event: KeyboardEvent): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.send();
    }
  }

  hasWarnings(msg: ChatMessage): boolean {
    return !!(msg.warnings && msg.warnings.length > 0);
  }

  private scrollToBottom(): void {
    setTimeout(() => {
      if (this.messageList) {
        this.messageList.nativeElement.scrollTop = this.messageList.nativeElement.scrollHeight;
      }
    }, 50);
  }
}