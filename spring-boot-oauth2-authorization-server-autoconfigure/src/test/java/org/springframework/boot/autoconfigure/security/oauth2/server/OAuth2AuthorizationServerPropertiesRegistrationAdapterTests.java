/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.boot.autoconfigure.security.oauth2.server;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerPropertiesRegistrationAdapter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationServerPropertiesRegistrationAdapterTests {

	@Test
	void getRegisteredClientsWhenValidParametersShouldAdapt() {
		OAuth2AuthorizationServerProperties properties = new OAuth2AuthorizationServerProperties();
		OAuth2AuthorizationServerProperties.Registration registration = createRegistration();
		properties.getRegistration().put("foo", registration);

		List<RegisteredClient> registeredClients = OAuth2AuthorizationServerPropertiesRegistrationAdapter
				.getRegisteredClients(properties);
		assertThat(registeredClients).hasSize(1);

		RegisteredClient registeredClient = registeredClients.get(0);
		assertThat(registeredClient.getClientId()).isEqualTo("foo");
		assertThat(registeredClient.getClientSecret()).isEqualTo("secret");
		assertThat(registeredClient.getClientAuthenticationMethods())
				.containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registeredClient.getAuthorizationGrantTypes())
				.containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registeredClient.getRedirectUris())
				.containsExactly("https://example.com/redirect");
		assertThat(registeredClient.getScopes())
				.containsExactly("user.read");

		assertThat(registeredClient.getClientSettings().isRequireProofKey()).isTrue();
		assertThat(registeredClient.getClientSettings().isRequireAuthorizationConsent()).isTrue();
		assertThat(registeredClient.getClientSettings().getJwkSetUrl()).isEqualTo("https://example.com/jwks");
		assertThat(registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm())
				.isEqualTo(SignatureAlgorithm.RS256);
		assertThat(registeredClient.getClientSettings().<Boolean>getSetting("client_setting1")).isTrue();
		assertThat(registeredClient.getClientSettings().<String>getSetting("client_setting2")).isEqualTo("string");

		assertThat(registeredClient.getTokenSettings().getAccessTokenFormat()).isEqualTo(OAuth2TokenFormat.REFERENCE);
		assertThat(registeredClient.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofSeconds(300));
		assertThat(registeredClient.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofHours(24));
		assertThat(registeredClient.getTokenSettings().isReuseRefreshTokens()).isEqualTo(true);
		assertThat(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm())
				.isEqualTo(SignatureAlgorithm.RS512);
		assertThat(registeredClient.getTokenSettings().<Boolean>getSetting("token_setting1")).isTrue();
		assertThat(registeredClient.getTokenSettings().<String>getSetting("token_setting2")).isEqualTo("string");
	}

	private OAuth2AuthorizationServerProperties.Registration createRegistration() {
		OAuth2AuthorizationServerProperties.Registration registration =
				new OAuth2AuthorizationServerProperties.Registration();
		registration.setClientId("foo");
		registration.setClientSecret("secret");
		registration.getClientAuthenticationMethod().add("client_secret_basic");
		registration.getAuthorizationGrantType().add("authorization_code");
		registration.getRedirectUri().add("https://example.com/redirect");
		registration.getScope().add("user.read");

		registration.getClientSettings().setRequireProofKey(true);
		registration.getClientSettings().setRequireAuthorizationConsent(true);
		registration.getClientSettings().setJwkSetUrl("https://example.com/jwks");
		registration.getClientSettings().setTokenEndpointAuthenticationSigningAlgorithm("rs256");
		registration.getClientSettings().getAdditionalSettings()
				.put("client_setting1", true);
		registration.getClientSettings().getAdditionalSettings()
				.put("client_setting2", "string");

		registration.getTokenSettings().setAccessTokenFormat("reference");
		registration.getTokenSettings().setAccessTokenTimeToLive(Duration.ofSeconds(300));
		registration.getTokenSettings().setRefreshTokenTimeToLive(Duration.ofHours(24));
		registration.getTokenSettings().setReuseRefreshTokens(true);
		registration.getTokenSettings().setIdTokenSignatureAlgorithm("rs512");
		registration.getTokenSettings().getAdditionalSettings()
				.put("token_setting1", true);
		registration.getTokenSettings().getAdditionalSettings()
				.put("token_setting2", "string");
		return registration;
	}

}
