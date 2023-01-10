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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Tests for {@link OAuth2AuthorizationServerProperties}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationServerPropertiesTests {

	private final OAuth2AuthorizationServerProperties properties = new OAuth2AuthorizationServerProperties();

	@Test
	void clientIdAbsentThrowsException() {
		OAuth2AuthorizationServerProperties.Registration registration =
				new OAuth2AuthorizationServerProperties.Registration();
		registration.getClientAuthenticationMethod().add("client_secret_basic");
		registration.getAuthorizationGrantType().add("authorization_code");
		this.properties.getRegistration().put("foo", registration);
		assertThatIllegalStateException().isThrownBy(this.properties::validate)
				.withMessage("Client id must not be empty.");
	}

	@Test
	void clientSecretAbsentShouldNotThrowException() {
		OAuth2AuthorizationServerProperties.Registration registration =
				new OAuth2AuthorizationServerProperties.Registration();
		registration.setClientId("foo");
		registration.getClientAuthenticationMethod().add("client_secret_basic");
		registration.getAuthorizationGrantType().add("authorization_code");
		this.properties.getRegistration().put("foo", registration);
		this.properties.validate();
	}

	@Test
	void clientAuthenticationMethodsEmptyThrowsException() {
		OAuth2AuthorizationServerProperties.Registration registration =
				new OAuth2AuthorizationServerProperties.Registration();
		registration.setClientId("foo");
		registration.getAuthorizationGrantType().add("authorization_code");
		this.properties.getRegistration().put("foo", registration);
		assertThatIllegalStateException().isThrownBy(this.properties::validate)
				.withMessage("Client authentication methods must not be empty.");
	}

	@Test
	void authorizationGrantTypesEmptyThrowsException() {
		OAuth2AuthorizationServerProperties.Registration registration =
				new OAuth2AuthorizationServerProperties.Registration();
		registration.setClientId("foo");
		registration.getClientAuthenticationMethod().add("client_secret_basic");
		this.properties.getRegistration().put("foo", registration);
		assertThatIllegalStateException().isThrownBy(this.properties::validate)
				.withMessage("Authorization grant types must not be empty.");
	}

}
