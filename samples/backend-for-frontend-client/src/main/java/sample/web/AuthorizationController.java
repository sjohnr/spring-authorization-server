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
package sample.web;

import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Steve Riesenberg
 * @since 0.2.3
 */
@RestController
public class AuthorizationController {

	private final WebClient webClient;
	private final String messagesBaseUri;
	private final String appBaseUri;

	public AuthorizationController(WebClient webClient,
			@Value("${messages.base-uri}") String messagesBaseUri,
			@Value("${app.base-uri}") String appBaseUri) {
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
		this.appBaseUri = appBaseUri;
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code", produces = MediaType.TEXT_HTML_VALUE)
	public Mono<ResponseEntity<Void>> authorizeAuthorizationCodeGrant(
			@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
					OAuth2AuthorizedClient authorizedClient) {
		ResponseEntity<Void> responseEntity = ResponseEntity.status(HttpStatus.FOUND)
				.header("Location", this.appBaseUri + "/authorize?grant_type=authorization_code")
				.build();
		return Mono.just(responseEntity);
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code", produces = MediaType.APPLICATION_JSON_VALUE)
	public Mono<String[]> authorizationCodeGrant(
			@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
					OAuth2AuthorizedClient authorizedClient) {
		return this.webClient.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class);
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials", produces = MediaType.TEXT_HTML_VALUE)
	public Mono<ResponseEntity<Void>> authorizeClientCredentialsGrant(
			@RegisteredOAuth2AuthorizedClient("messaging-client-client-credentials")
					OAuth2AuthorizedClient authorizedClient) {
		ResponseEntity<Void> responseEntity = ResponseEntity.status(HttpStatus.FOUND)
				.header("Location", this.appBaseUri + "/authorize?grant_type=client_credentials")
				.build();
		return Mono.just(responseEntity);
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials", produces = MediaType.APPLICATION_JSON_VALUE)
	public Mono<String[]> clientCredentialsGrant() {
		return this.webClient.get()
				.uri(this.messagesBaseUri)
				.attributes(clientRegistrationId("messaging-client-client-credentials"))
				.retrieve()
				.bodyToMono(String[].class);
	}

}
