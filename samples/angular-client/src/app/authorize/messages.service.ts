import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { OidcSecurityService } from 'angular-auth-oidc-client';

@Injectable({
  providedIn: 'root'
})
export class MessagesService {
  constructor(private http: HttpClient, private oidcSecurityService: OidcSecurityService) { }

  getMessages(): Observable<string[]> {
    // TODO: Request data from resource server
    return of(['Please log in.']);
  }
}
