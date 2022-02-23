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
  accessToken = '';
  username = '';

  constructor(private http: HttpClient, private oidcSecurityService: OidcSecurityService) {}

  ngOnInit() {
    this.oidcSecurityService.checkAuth().subscribe(({ isAuthenticated, userData, accessToken, idToken }) => {
      this.isAuthenticated = isAuthenticated;
      this.accessToken = accessToken;
      if (userData) {
        this.username = userData.sub;
      }

      // If unauthenticated via public client, check auth status with gateway
      if (!isAuthenticated) {
        this.http.get<any>('http://127.0.0.1:8080/userinfo', {
          withCredentials: true
        }).subscribe(response => {
          this.isAuthenticated = true;
          this.username = response.name;
        });
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
