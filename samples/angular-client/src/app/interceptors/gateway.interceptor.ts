import { Injectable } from '@angular/core';
import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class GatewayInterceptor implements HttpInterceptor {

  constructor() {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (req.url.startsWith('http')) {
      return next.handle(req);
    }

    const newReq = req.clone({
      url: 'http://127.0.0.1:8080' + req.url,
      withCredentials: true
    });

    return next.handle(newReq);
  }
}
