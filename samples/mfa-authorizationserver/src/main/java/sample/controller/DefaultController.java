/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.controller;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import sample.model.UserInfo;
import sample.security.CurrentUser;
import sample.security.MultiFactorAuthentication;
import sample.security.MultiFactorAuthenticationHandler;
import sample.service.AuthenticatorService;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Steve Riesenberg
 */
@Controller
public class DefaultController {

	private final AuthenticatorService authenticatorService;

	private final AuthenticationSuccessHandler authenticationSuccessHandler;

	private final PasswordEncoder passwordEncoder;

	private final String failedAuthenticationSecret;

	private final AuthenticationSuccessHandler authenticatorSuccessHandler =
			new MultiFactorAuthenticationHandler("/security-question", "SECURITY_QUESTION_REQUIRED");

	private final AuthenticationFailureHandler authenticatorFailureHandler =
			new SimpleUrlAuthenticationFailureHandler("/authenticator?error");

	private final AuthenticationFailureHandler securityQuestionFailureHandler =
			new SimpleUrlAuthenticationFailureHandler("/security-question?error");

	public DefaultController(
		AuthenticatorService authenticatorService,
		AuthenticationSuccessHandler authenticationSuccessHandler,
		PasswordEncoder passwordEncoder
	) {
		this.authenticatorService = authenticatorService;
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		this.passwordEncoder = passwordEncoder;
		this.failedAuthenticationSecret = authenticatorService.generateSecret();
	}

	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping("/profile")
	public String profile() {
		return "profile";
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/authenticator")
	public String authenticator() {
		return "authenticator";
	}

	@PostMapping("/authenticator")
	public void validateCode(@RequestParam("code") String code,
			HttpServletRequest request,
			HttpServletResponse response,
			MultiFactorAuthentication authentication) throws ServletException, IOException {
		if (authentication.getPrincipal() instanceof UserInfo) {
			UserInfo user = (UserInfo) authentication.getPrincipal();
			for (String secret : user.getSecrets()) {
				if (this.authenticatorService.check(secret, code)) {
					this.authenticatorSuccessHandler.onAuthenticationSuccess(request, response, authentication.getPrimaryAuthentication());
					return;
				}
			}
		} else {
			this.authenticatorService.check(this.failedAuthenticationSecret, code);
		}

		authenticatorFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));
	}

	@GetMapping("/security-question")
	public String securityQuestion(@CurrentUser UserInfo userInfo, Model model) {
		model.addAttribute("question", userInfo.getSecurityQuestion());
		return "security-question";
	}

	@PostMapping("/security-question")
	public void validateAnswer(@RequestParam("answer") String answer,
			HttpServletRequest request,
			HttpServletResponse response,
			MultiFactorAuthentication authentication) throws ServletException, IOException {
		if (authentication.getPrincipal() instanceof UserInfo) {
			UserInfo user = (UserInfo) authentication.getPrincipal();
			if (this.passwordEncoder.matches(answer, user.getAnswer())) {
				SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
				securityContext.setAuthentication(authentication.getPrimaryAuthentication());
				SecurityContextHolder.setContext(securityContext);
				this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication.getPrimaryAuthentication());
				return;
			}
		} else {
			this.passwordEncoder.matches(this.failedAuthenticationSecret, answer);
		}

		this.securityQuestionFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));
	}

}
