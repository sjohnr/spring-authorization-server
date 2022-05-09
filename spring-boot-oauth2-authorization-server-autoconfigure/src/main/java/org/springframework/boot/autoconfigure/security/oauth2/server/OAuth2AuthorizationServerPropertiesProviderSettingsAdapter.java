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

import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;

/**
 * Adapter class to convert {@link OAuth2AuthorizationServerProperties.ProviderSettings} to a {@link ProviderSettings}.
 *
 * @author Steve Riesenberg
 */
public final class OAuth2AuthorizationServerPropertiesProviderSettingsAdapter {

	private OAuth2AuthorizationServerPropertiesProviderSettingsAdapter() {
	}

	public static ProviderSettings getProviderSettings(OAuth2AuthorizationServerProperties properties) {
		PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
		OAuth2AuthorizationServerProperties.ProviderSettings providerSettings = properties.getProviderSettings();
		ProviderSettings.Builder builder = ProviderSettings.builder();
		map.from(providerSettings::getIssuer).to(builder::issuer);
		map.from(providerSettings::getAuthorizationEndpoint).to(builder::authorizationEndpoint);
		map.from(providerSettings::getTokenEndpoint).to(builder::tokenEndpoint);
		map.from(providerSettings::getJwkSetEndpoint).to(builder::jwkSetEndpoint);
		map.from(providerSettings::getTokenRevocationEndpoint).to(builder::tokenRevocationEndpoint);
		map.from(providerSettings::getTokenIntrospectionEndpoint).to(builder::tokenIntrospectionEndpoint);
		map.from(providerSettings::getOidcClientRegistrationEndpoint).to(builder::oidcClientRegistrationEndpoint);
		map.from(providerSettings::getOidcUserInfoEndpoint).to(builder::oidcUserInfoEndpoint);
		builder.settings(settings -> settings.putAll(providerSettings.getAdditionalSettings()));
		return builder.build();
	}

}
