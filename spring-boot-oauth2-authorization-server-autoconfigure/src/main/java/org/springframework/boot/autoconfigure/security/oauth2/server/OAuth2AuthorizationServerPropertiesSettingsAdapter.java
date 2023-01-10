/*
 * Copyright 2020-2023 the original author or authors.
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

import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Adapter class to convert {@link OAuth2AuthorizationServerProperties.AuthorizationServerSettings} to a
 * {@link AuthorizationServerSettings}.
 *
 * @author Steve Riesenberg
 */
public final class OAuth2AuthorizationServerPropertiesSettingsAdapter {

	private OAuth2AuthorizationServerPropertiesSettingsAdapter() {
	}

	public static AuthorizationServerSettings getAuthorizationServerSettings(OAuth2AuthorizationServerProperties properties) {
		PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
		OAuth2AuthorizationServerProperties.AuthorizationServerSettings settings = properties.getSettings();
		AuthorizationServerSettings.Builder builder = AuthorizationServerSettings.builder();
		map.from(settings::getIssuer).to(builder::issuer);
		map.from(settings::getAuthorizationEndpoint).to(builder::authorizationEndpoint);
		map.from(settings::getTokenEndpoint).to(builder::tokenEndpoint);
		map.from(settings::getJwkSetEndpoint).to(builder::jwkSetEndpoint);
		map.from(settings::getTokenRevocationEndpoint).to(builder::tokenRevocationEndpoint);
		map.from(settings::getTokenIntrospectionEndpoint).to(builder::tokenIntrospectionEndpoint);
		map.from(settings::getOidcClientRegistrationEndpoint).to(builder::oidcClientRegistrationEndpoint);
		map.from(settings::getOidcUserInfoEndpoint).to(builder::oidcUserInfoEndpoint);
		builder.settings((s) -> s.putAll(settings.getAdditionalSettings()));
		return builder.build();
	}

}
