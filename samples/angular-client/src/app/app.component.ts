import { Component, OnInit } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  title = 'angular-oidc-demo';
  isAuthenticated = false;
  username = '';

  constructor(private http: HttpClient, private oidcSecurityService: OidcSecurityService) {}

  ngOnInit() {
    // TODO: Check auth
  }

  login() {
    // TODO: Log in
  }

  logout() {
    // TODO: Log out
  }
}
