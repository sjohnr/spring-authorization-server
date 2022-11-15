import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { AuthConfigModule } from './auth/auth-config.module';
import { IndexComponent } from './index/index.component';
import { AuthorizeComponent } from './authorize/authorize.component';
import { HttpClientModule } from '@angular/common/http';

@NgModule({
  declarations: [
    AppComponent,
    IndexComponent,
    AuthorizeComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    AppRoutingModule,
    AuthConfigModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
