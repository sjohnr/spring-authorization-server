/*
 * Copyright 2020-2022 the original author or authors.
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
package sample.config;

import reactor.core.publisher.Mono;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.DelegateEntry;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.HttpStatusReturningServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfServerLogoutHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.web.server.WebFilter;

/**
 * @author Steve Riesenberg
 * @since 0.2.3
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		// @formatter:off
		http
			.authorizeExchange(authorizeExchange ->
				authorizeExchange.anyExchange().authenticated()
			)
			.exceptionHandling(exceptionHandling ->
				exceptionHandling.authenticationEntryPoint(authenticationEntryPoint())
			)
			.csrf(csrf ->
				csrf.csrfTokenRepository(csrfTokenRepository())
			)
			.cors(Customizer.withDefaults())
			.oauth2Login(oauth2 ->
				oauth2.authenticationSuccessHandler(authenticationSuccessHandler())
			)
			.logout(logout ->
				logout
					.logoutHandler(logoutHandler())
					.logoutSuccessHandler(logoutSuccessHandler())
			)
			.oauth2Client(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	private ServerAuthenticationEntryPoint authenticationEntryPoint() {
		RedirectServerAuthenticationEntryPoint webAuthenticationEntryPoint =
				new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/messaging-client-oidc");
		MediaTypeServerWebExchangeMatcher textHtmlMatcher =
				new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
		textHtmlMatcher.setUseEquals(true);

		return new DelegatingServerAuthenticationEntryPoint(
				new DelegateEntry(textHtmlMatcher, webAuthenticationEntryPoint));
	}

	private ServerAuthenticationSuccessHandler authenticationSuccessHandler() {
		return new RedirectServerAuthenticationSuccessHandler("http://127.0.0.1:4200");
	}

	private ServerLogoutHandler logoutHandler() {
		return new DelegatingServerLogoutHandler(
				new SecurityContextServerLogoutHandler(),
				new CsrfServerLogoutHandler(csrfTokenRepository()));
	}

	private ServerLogoutSuccessHandler logoutSuccessHandler() {
		return new HttpStatusReturningServerLogoutSuccessHandler(HttpStatus.OK);
	}

	private CookieServerCsrfTokenRepository csrfTokenRepository() {
		return CookieServerCsrfTokenRepository.withHttpOnlyFalse();
	}

	@Bean
	public ReactiveUserDetailsService userDetailsService() {
		// @formatter:off
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		// @formatter:on
		return new MapReactiveUserDetailsService(user);
	}

	@Bean
	public WebFilter csrfTokenSubscriberWebFilter() {
		return (exchange, chain) -> {
			Mono<CsrfToken> csrfAttribute = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
			return csrfAttribute.then(chain.filter(exchange));
		};
	}

}
