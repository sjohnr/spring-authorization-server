import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class MessagesService {
  constructor(private http: HttpClient) { }

  getMessages(): Observable<string[]> {
    // TODO: Request data from backend
    return of(['Please log in.']);
  }
}
