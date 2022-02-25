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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Steve Riesenberg
 * @since 0.2.3
 */
@Configuration
public class WebClientConfig {

	@Bean
	public WebClient webClient(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
		ServerOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		return WebClient.builder()
				.filter(oauth2Client)
				.build();
	}

	@Bean
	@Primary // Needed because of GatewayReactiveOAuth2AutoConfiguration
	public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
				ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
						.clientCredentials()
						.build();

		DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager =
				new DefaultReactiveOAuth2AuthorizedClientManager(
						clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		return authorizedClientManager;
	}

}
