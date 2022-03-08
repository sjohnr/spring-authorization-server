import { NgModule } from '@angular/core';
import { AuthModule } from 'angular-auth-oidc-client';


@NgModule({
  imports: [AuthModule.forRoot({
    config: {
      authority: 'http://localhost:9000',
      redirectUrl: window.location.origin,
      postLogoutRedirectUri: window.location.origin,
      clientId: 'public-client',
      scope: 'openid message.read message.write', // 'openid profile ' + your scopes
      responseType: 'code',
      silentRenew: true,
      silentRenewUrl: window.location.origin + '/silent-renew.html',
      renewTimeBeforeTokenExpiresInSeconds: 10,
      autoUserInfo: false
    }
  })],
  exports: [AuthModule],
})
export class AuthConfigModule {
}
