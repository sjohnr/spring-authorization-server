import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { MessagesService } from './messages.service';

@Component({
  selector: 'app-authorize',
  templateUrl: './authorize.component.html',
  styleUrls: ['./authorize.component.scss']
})
export class AuthorizeComponent implements OnInit {
  messages: string[] = [];

  constructor(private route: ActivatedRoute, private messagesService: MessagesService) { }

  ngOnInit(): void {
    this.messagesService.getMessages().subscribe(messages => this.messages = messages);
  }
}
