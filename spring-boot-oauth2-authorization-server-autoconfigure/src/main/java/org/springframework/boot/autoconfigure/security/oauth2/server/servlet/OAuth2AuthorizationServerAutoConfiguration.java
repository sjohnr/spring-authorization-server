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
package org.springframework.boot.autoconfigure.security.oauth2.server.servlet;

import java.util.List;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerPropertiesProviderSettingsAdapter;
import org.springframework.boot.autoconfigure.security.oauth2.server.OAuth2AuthorizationServerPropertiesRegistrationAdapter;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for OAuth2 authorization server support.
 *
 * <p>
 * <strong>Note:</strog> This configuration and {@link OAuth2BearerTokenEndpointAutoConfiguration} work together to
 * ensure that the {@link org.springframework.security.config.annotation.ObjectPostProcessor} is defined
 * <strong>BEFORE</strong> {@link UserDetailsServiceAutoConfiguration} so that a
 * {@link org.springframework.security.core.userdetails.UserDetailsService} can be created if necessary.
 *
 * @author Steve Riesenberg
 * @see OAuth2BearerTokenEndpointAutoConfiguration
 */
@Configuration(proxyBeanMethods = false)
@AutoConfigureBefore({ SecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class, SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties(OAuth2AuthorizationServerProperties.class)
@ConditionalOnClass(OAuth2Authorization.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Import(ObjectPostProcessorConfiguration.class)
public class OAuth2AuthorizationServerAutoConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@ConditionalOnMissingBean(name = "authorizationServerSecurityFilterChain")
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http.formLogin(Customizer.withDefaults()).build();
	}

	@Bean
	@Order(SecurityProperties.BASIC_AUTH_ORDER)
	@ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	@Bean
	@ConditionalOnMissingBean
	RegisteredClientRepository registeredClientRepository(OAuth2AuthorizationServerProperties properties) {
		List<RegisteredClient> registeredClients = OAuth2AuthorizationServerPropertiesRegistrationAdapter
				.getRegisteredClients(properties);
		return new InMemoryRegisteredClientRepository(registeredClients);
	}

	@Bean
	@ConditionalOnMissingBean
	ProviderSettings providerSettings(OAuth2AuthorizationServerProperties properties) {
		return OAuth2AuthorizationServerPropertiesProviderSettingsAdapter.getProviderSettings(properties);
	}

}
