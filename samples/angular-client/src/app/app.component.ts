import { Component, OnInit } from '@angular/core';
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

  constructor(private http: HttpClient) {}

  ngOnInit() {
    // TODO: Check auth
  }

  login() {
    // TODO: Log in
    return false;
  }

  logout() {
    this.isAuthenticated = false;
    return false;
  }
}
