import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { catchError, Observable, of } from 'rxjs';
import { OidcSecurityService } from 'angular-auth-oidc-client';

@Injectable({
  providedIn: 'root'
})
export class MessagesService {
  constructor(private http: HttpClient, private oidcSecurityService: OidcSecurityService) { }

  getMessagesWithAuthorizationCodeUsingPublicClient(): Observable<string[]> {
    if (this.oidcSecurityService.isAuthenticated()) {
      let accessToken = this.oidcSecurityService.getAccessToken();
      return this.http.get<string[]>('http://localhost:8090/messages', {
        headers: new HttpHeaders(`Authorization: Bearer ${accessToken}`)
      }).pipe(catchError((error) => {
        console.error(error);
        // this.oidcSecurityService.authorize();
        return of(['Please log in.']);
      }));
    } else {
      // this.oidcSecurityService.authorize();
      return of(['Please log in.']);
    }
  }

  getMessagesWithAuthorizationCodeUsingConfidentialClient(): Observable<string[]> {
    return this.http.get<string[]>('http://127.0.0.1:8080/authorize?grant_type=authorization_code', {
      withCredentials: true
    }).pipe(catchError((error) => {
      console.error(error);
      // window.location.href = 'http://127.0.0.1:8080/authorize?grant_type=authorization_code';
      return of(['Please log in.']);
    }));
  }

  getMessagesWithClientCredentialsUsingConfidentialClient(): Observable<string[]> {
    return this.http.get<string[]>('http://127.0.0.1:8080/authorize?grant_type=client_credentials', {
      withCredentials: true
    }).pipe(catchError((error) => {
      console.error(error);
      // window.location.href = 'http://127.0.0.1:8080/authorize?grant_type=client_credentials';
      return of(['Please log in.']);
    }));
  }

  getMessagesWithAuthorizationCodeUsingTokenRelay(): Observable<string[]> {
    return this.http.get<string[]>('http://127.0.0.1:8080/messages', {
      withCredentials: true
    }).pipe(catchError((error) => {
      console.error(error);
      // window.location.href = 'http://127.0.0.1:8080';
      return of(['Please log in.']);
    }));
  }
}
