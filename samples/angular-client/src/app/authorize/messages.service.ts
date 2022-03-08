import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { OidcSecurityService } from 'angular-auth-oidc-client';

@Injectable({
  providedIn: 'root'
})
export class MessagesService {
  constructor(private http: HttpClient, private oidcSecurityService: OidcSecurityService) { }

  getMessages(): Observable<string[]> {
    if (this.oidcSecurityService.isAuthenticated()) {
      let accessToken = this.oidcSecurityService.getAccessToken();
      return this.http.get<string[]>('http://localhost:8090/messages', {
        headers: new HttpHeaders(`Authorization: Bearer ${accessToken}`)
      });
    } else {
      return of(['Please log in.']);
    }
  }
}
