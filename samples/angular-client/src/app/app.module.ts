import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { AuthConfigModule } from './auth/auth-config.module';
import { IndexComponent } from './index/index.component';
import { AuthorizeComponent } from './authorize/authorize.component';
import { HTTP_INTERCEPTORS, HttpClientModule, HttpClientXsrfModule } from '@angular/common/http';
import { ReactiveFormsModule } from '@angular/forms';
import { GatewayInterceptor } from './interceptors/gateway.interceptor';

@NgModule({
  declarations: [
    AppComponent,
    IndexComponent,
    AuthorizeComponent
  ],
  imports: [
    BrowserModule,
    ReactiveFormsModule,
    HttpClientModule,
    HttpClientXsrfModule,
    AppRoutingModule,
    AuthConfigModule
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: GatewayInterceptor, multi: true }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
