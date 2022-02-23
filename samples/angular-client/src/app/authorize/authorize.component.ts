import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { MessagesService } from './messages.service';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-authorize',
  templateUrl: './authorize.component.html',
  styleUrls: ['./authorize.component.scss']
})
export class AuthorizeComponent implements OnInit {
  grant_type = '';
  client_type = '';
  messages: string[] = [];

  constructor(private route: ActivatedRoute, private messagesService: MessagesService) { }

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      this.grant_type = params['grant_type'];
      this.client_type = params['client_type'];
      this.callApi();
    });
  }

  private callApi(): void {
    let observable: Observable<string[]>;
    if (this.client_type === 'public') {
      observable = this.messagesService.getMessagesWithAuthorizationCodeUsingPublicClient();
    } else if (this.client_type === 'token_relay') {
      observable = this.messagesService.getMessagesWithAuthorizationCodeUsingTokenRelay();
    } else if (this.grant_type === 'authorization_code') {
      observable = this.messagesService.getMessagesWithAuthorizationCodeUsingConfidentialClient();
    } else {
      observable = this.messagesService.getMessagesWithClientCredentialsUsingConfidentialClient();
    }
    observable.subscribe(messages => this.messages = messages);
  }
}
