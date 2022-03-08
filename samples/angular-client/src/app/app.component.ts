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
    this.oidcSecurityService.checkAuth().subscribe(({ isAuthenticated, userData }) => {
      this.isAuthenticated = isAuthenticated;
      if (userData) {
        this.username = userData.sub;
      }
    });
  }

  login() {
    this.oidcSecurityService.authorize();
    return false;
  }

  logout() {
    this.oidcSecurityService.logoff();
    this.isAuthenticated = false;
    return false;
  }
}
