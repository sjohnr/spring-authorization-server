/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.honest.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * @author Steve Riesenberg
 */
class FormPostResponseModeAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		// @formatter:off
		String html =
				"<html>\n" +
						"  <head><title>Authorization Success</title></head>\n" +
						"  <body onload=\"javascript:document.forms[0].submit()\">\n" +
						"    <form method=\"post\" action=\"" + authorizationCodeRequestAuthentication.getRedirectUri() + "\">\n" +
						"      <input type=\"hidden\" name=\"state\" value=\"" + authorizationCodeRequestAuthentication.getState() + "\"/>\n" +
						"      <input type=\"hidden\" name=\"code\" value=\"" + authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue() + "\"/>\n" +
						"    </form>\n" +
						"  </body>\n" +
						"</html>";
		// @formatter:on

		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
		response.getWriter().flush();
	}

}
