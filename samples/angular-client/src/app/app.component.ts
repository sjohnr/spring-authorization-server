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
    this.http.get<any>('/userinfo').subscribe((user) => {
      this.isAuthenticated = true;
      this.username = user.name;
    });
  }

  login() {
    window.location.href = 'http://127.0.0.1:8080';
    return false;
  }

  logout() {
    this.http.post('/logout', null).subscribe(() => this.isAuthenticated = false);
    return false;
  }
}
