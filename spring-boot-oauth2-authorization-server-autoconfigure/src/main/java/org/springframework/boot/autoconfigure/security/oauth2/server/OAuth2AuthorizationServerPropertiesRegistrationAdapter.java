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
package org.springframework.boot.autoconfigure.security.oauth2.server;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerProperties.Registration;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.util.CollectionUtils;

/**
 * Adapter class to convert {@link Registration} to a {@link RegisteredClient}.
 *
 * @author Steve Riesenberg
 */
public final class OAuth2AuthorizationServerPropertiesRegistrationAdapter {

	private OAuth2AuthorizationServerPropertiesRegistrationAdapter() {
	}

	public static List<RegisteredClient> getRegisteredClients(OAuth2AuthorizationServerProperties properties) {
		List<RegisteredClient> registeredClients = new ArrayList<>();
		properties.getRegistration().forEach((registrationId, registration) ->
				registeredClients.add(getRegisteredClient(registrationId, registration)));
		return registeredClients;
	}

	private static RegisteredClient getRegisteredClient(String registrationId, Registration registration) {
		PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
		RegisteredClient.Builder builder = RegisteredClient.withId(registrationId);
		map.from(registration::getClientId).to(builder::clientId);
		map.from(registration::getClientSecret).to(builder::clientSecret);
		if (!CollectionUtils.isEmpty(registration.getClientAuthenticationMethod())) {
			registration.getClientAuthenticationMethod().forEach(clientAuthenticationMethod ->
					map.from(clientAuthenticationMethod)
							.as(OAuth2AuthorizationServerPropertiesRegistrationAdapter::clientAuthenticationMethod)
							.to(builder::clientAuthenticationMethod));
		}
		if (!CollectionUtils.isEmpty(registration.getAuthorizationGrantType())) {
			registration.getAuthorizationGrantType().forEach(authorizationGrantType ->
					map.from(authorizationGrantType)
							.as(OAuth2AuthorizationServerPropertiesRegistrationAdapter::authorizationGrantType)
							.to(builder::authorizationGrantType));
		}
		if (!CollectionUtils.isEmpty(registration.getRedirectUri())) {
			registration.getRedirectUri().forEach(redirectUri -> map.from(redirectUri).to(builder::redirectUri));
		}
		if (!CollectionUtils.isEmpty(registration.getScope())) {
			registration.getScope().forEach(scope -> map.from(scope).to(builder::scope));
		}
		builder.clientSettings(getClientSettings(registration, map));
		builder.tokenSettings(getTokenSettings(registration, map));
		return builder.build();
	}

	private static ClientAuthenticationMethod clientAuthenticationMethod(String clientAuthenticationMethod) {
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_JWT;
		} else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.PRIVATE_KEY_JWT;
		} else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.NONE;
		} else {
			return new ClientAuthenticationMethod(clientAuthenticationMethod);
		}
	}

	private static AuthorizationGrantType authorizationGrantType(String authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.AUTHORIZATION_CODE;
		} else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.CLIENT_CREDENTIALS;
		} else {
			return new AuthorizationGrantType(authorizationGrantType);
		}
	}

	private static ClientSettings getClientSettings(Registration registration, PropertyMapper map) {
		OAuth2AuthorizationServerProperties.ClientSettings clientSettings = registration.getClientSettings();
		ClientSettings.Builder builder = ClientSettings.builder();
		map.from(clientSettings::isRequireProofKey).to(builder::requireProofKey);
		map.from(clientSettings::isRequireAuthorizationConsent).to(builder::requireAuthorizationConsent);
		map.from(clientSettings::getJwkSetUrl).to(builder::jwkSetUrl);
		map.from(clientSettings::getTokenEndpointAuthenticationSigningAlgorithm)
				.as(OAuth2AuthorizationServerPropertiesRegistrationAdapter::jwsAlgorithm)
				.to(builder::tokenEndpointAuthenticationSigningAlgorithm);
		builder.settings(settings -> settings.putAll(clientSettings.getAdditionalSettings()));
		return builder.build();
	}

	private static TokenSettings getTokenSettings(Registration registration, PropertyMapper map) {
		OAuth2AuthorizationServerProperties.TokenSettings tokenSettings = registration.getTokenSettings();
		TokenSettings.Builder builder = TokenSettings.builder();
		map.from(tokenSettings::getAccessTokenTimeToLive).to(builder::accessTokenTimeToLive);
		map.from(tokenSettings::getAccessTokenFormat).as(OAuth2TokenFormat::new).to(builder::accessTokenFormat);
		map.from(tokenSettings::isReuseRefreshTokens).to(builder::reuseRefreshTokens);
		map.from(tokenSettings::getRefreshTokenTimeToLive).to(builder::refreshTokenTimeToLive);
		map.from(tokenSettings::getIdTokenSignatureAlgorithm)
				.as(OAuth2AuthorizationServerPropertiesRegistrationAdapter::signatureAlgorithm)
				.to(builder::idTokenSignatureAlgorithm);
		builder.settings(settings -> settings.putAll(tokenSettings.getAdditionalSettings()));
		return builder.build();
	}

	private static JwsAlgorithm jwsAlgorithm(String signingAlgorithm) {
		String name = signingAlgorithm.toUpperCase();
		JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.from(name);
		if (jwsAlgorithm == null) {
			jwsAlgorithm = MacAlgorithm.from(name);
		}
		return jwsAlgorithm;
	}

	private static SignatureAlgorithm signatureAlgorithm(String signatureAlgorithm) {
		return SignatureAlgorithm.from(signatureAlgorithm.toUpperCase());
	}

}
