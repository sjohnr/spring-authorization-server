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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

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

	@GetMapping(value = "/authorize", produces = MediaType.TEXT_HTML_VALUE)
	public Mono<ResponseEntity<Void>> authorizeClient() {
		ResponseEntity<Void> responseEntity = ResponseEntity.status(HttpStatus.FOUND)
				.header("Location", this.appBaseUri + "/authorize")
				.build();
		return Mono.just(responseEntity);
	}

}
