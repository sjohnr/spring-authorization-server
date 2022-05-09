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

import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * OAuth 2.0 authorization server properties.
 *
 * @author Steve Riesenberg
 */
@ConfigurationProperties(prefix = "spring.security.oauth2.authorizationserver")
public class OAuth2AuthorizationServerProperties implements InitializingBean {

	/**
	 * Registered clients of the authorization server.
	 */
	private final Map<String, Registration> registration = new HashMap<>();

	/**
	 * Configuration settings of the authorization server (provider).
	 */
	private final ProviderSettings providerSettings = new ProviderSettings();

	public Map<String, Registration> getRegistration() {
		return this.registration;
	}

	public ProviderSettings getProviderSettings() {
		return providerSettings;
	}

	@Override
	public void afterPropertiesSet() {
		validate();
	}

	private void validate() {
		getRegistration().values().forEach(this::validateRegistration);
	}

	private void validateRegistration(Registration registration) {
		if (!StringUtils.hasText(registration.getClientId())) {
			throw new IllegalStateException("Client id must not be empty.");
		}
		if (CollectionUtils.isEmpty(registration.getAuthorizationGrantType())) {
			throw new IllegalStateException("Authorization grant types must not be empty");
		}
	}

	/**
	 * A registered client.
	 */
	public static class Registration {

		/**
		 * Client ID for the registration.
		 */
		private String clientId;

		/**
		 * Client secret of the registration. May be left blank for a public client.
		 */
		private String clientSecret;

		/**
		 * Client authentication method(s) that the client may use.
		 */
		private Set<String> clientAuthenticationMethod = new HashSet<>();

		/**
		 * Authorization grant type(s) that the client may use.
		 */
		private Set<String> authorizationGrantType = new HashSet<>();

		/**
		 * Redirect URI(s) that the client may use in redirect-based flows.
		 */
		private Set<String> redirectUri = new HashSet<>();

		/**
		 * Scope(s) that the client may use.
		 */
		private Set<String> scope = new HashSet<>();

		/**
		 * Client configuration settings.
		 */
		private ClientSettings clientSettings = new ClientSettings();

		/**
		 * Token configuration settings.
		 */
		private TokenSettings tokenSettings = new TokenSettings();

		public String getClientId() {
			return this.clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public String getClientSecret() {
			return this.clientSecret;
		}

		public void setClientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
		}

		public Set<String> getClientAuthenticationMethod() {
			return this.clientAuthenticationMethod;
		}

		public void setClientAuthenticationMethod(Set<String> clientAuthenticationMethod) {
			this.clientAuthenticationMethod = clientAuthenticationMethod;
		}

		public Set<String> getAuthorizationGrantType() {
			return this.authorizationGrantType;
		}

		public void setAuthorizationGrantType(Set<String> authorizationGrantType) {
			this.authorizationGrantType = authorizationGrantType;
		}

		public Set<String> getRedirectUri() {
			return this.redirectUri;
		}

		public void setRedirectUri(Set<String> redirectUri) {
			this.redirectUri = redirectUri;
		}

		public Set<String> getScope() {
			return this.scope;
		}

		public void setScope(Set<String> scope) {
			this.scope = scope;
		}

		public ClientSettings getClientSettings() {
			return this.clientSettings;
		}

		public void setClientSettings(ClientSettings clientSettings) {
			this.clientSettings = clientSettings;
		}

		public TokenSettings getTokenSettings() {
			return this.tokenSettings;
		}

		public void setTokenSettings(TokenSettings tokenSettings) {
			this.tokenSettings = tokenSettings;
		}

	}

	/**
	 * Client configuration settings.
	 */
	public static class ClientSettings {

		/**
		 * Whether the client is required to provide a proof key challenge and verifier when performing the
		 * Authorization Code Grant flow.
		 */
		private boolean requireProofKey;

		/**
		 * Whether authorization consent is required when the client requests access.
		 */
		private boolean requireAuthorizationConsent;

		/**
		 * The URL for the client's JSON Web Key Set.
		 */
		private String jwkSetUrl;

		/**
		 * The JWS algorithm that must be used for signing the JWT used to authenticate the client at the Token Endpoint
		 * for the {@code private_key_jwt} and {@code client_secret_jwt} authentication methods.
		 */
		private String tokenEndpointAuthenticationSigningAlgorithm;

		/**
		 * Additional settings.
		 */
		private Map<String, Object> additionalSettings = new HashMap<>();

		public boolean isRequireProofKey() {
			return this.requireProofKey;
		}

		public void setRequireProofKey(boolean requireProofKey) {
			this.requireProofKey = requireProofKey;
		}

		public boolean isRequireAuthorizationConsent() {
			return this.requireAuthorizationConsent;
		}

		public void setRequireAuthorizationConsent(boolean requireAuthorizationConsent) {
			this.requireAuthorizationConsent = requireAuthorizationConsent;
		}

		public String getJwkSetUrl() {
			return this.jwkSetUrl;
		}

		public void setJwkSetUrl(String jwkSetUrl) {
			this.jwkSetUrl = jwkSetUrl;
		}

		public String getTokenEndpointAuthenticationSigningAlgorithm() {
			return this.tokenEndpointAuthenticationSigningAlgorithm;
		}

		public void setTokenEndpointAuthenticationSigningAlgorithm(String tokenEndpointAuthenticationSigningAlgorithm) {
			this.tokenEndpointAuthenticationSigningAlgorithm = tokenEndpointAuthenticationSigningAlgorithm;
		}

		public Map<String, Object> getAdditionalSettings() {
			return this.additionalSettings;
		}

		public void setAdditionalSettings(Map<String, Object> additionalSettings) {
			this.additionalSettings = additionalSettings;
		}

	}

	/**
	 * Token configuration settings.
	 */
	public static class TokenSettings {

		/**
		 * The time-to-live for an access token.
		 */
		private Duration accessTokenTimeToLive;

		/**
		 * The token format for an access token.
		 */
		private String accessTokenFormat;

		/**
		 * Whether refresh tokens are reused or a new refresh token is issued when returning the access token response.
		 */
		private boolean reuseRefreshTokens;

		/**
		 * The time-to-live for a refresh token.
		 */
		private Duration refreshTokenTimeToLive;

		/**
		 * The JWS algorithm for signing the ID Token.
		 */
		private String idTokenSignatureAlgorithm;

		/**
		 * Additional settings.
		 */
		private Map<String, Object> additionalSettings = new HashMap<>();

		public Duration getAccessTokenTimeToLive() {
			return this.accessTokenTimeToLive;
		}

		public void setAccessTokenTimeToLive(Duration accessTokenTimeToLive) {
			this.accessTokenTimeToLive = accessTokenTimeToLive;
		}

		public String getAccessTokenFormat() {
			return this.accessTokenFormat;
		}

		public void setAccessTokenFormat(String accessTokenFormat) {
			this.accessTokenFormat = accessTokenFormat;
		}

		public boolean isReuseRefreshTokens() {
			return this.reuseRefreshTokens;
		}

		public void setReuseRefreshTokens(boolean reuseRefreshTokens) {
			this.reuseRefreshTokens = reuseRefreshTokens;
		}

		public Duration getRefreshTokenTimeToLive() {
			return this.refreshTokenTimeToLive;
		}

		public void setRefreshTokenTimeToLive(Duration refreshTokenTimeToLive) {
			this.refreshTokenTimeToLive = refreshTokenTimeToLive;
		}

		public String getIdTokenSignatureAlgorithm() {
			return this.idTokenSignatureAlgorithm;
		}

		public void setIdTokenSignatureAlgorithm(String idTokenSignatureAlgorithm) {
			this.idTokenSignatureAlgorithm = idTokenSignatureAlgorithm;
		}

		public Map<String, Object> getAdditionalSettings() {
			return this.additionalSettings;
		}

		public void setAdditionalSettings(Map<String, Object> additionalSettings) {
			this.additionalSettings = additionalSettings;
		}

	}

	/**
	 * Provider configuration settings.
	 */
	public static class ProviderSettings {

		/**
		 * The URL of the Provider's Issuer Identifier.
		 */
		private String issuer;

		/**
		 * The Provider's OAuth 2.0 Authorization endpoint.
		 */
		private String authorizationEndpoint;

		/**
		 * The Provider's OAuth 2.0 Token endpoint.
		 */
		private String tokenEndpoint;

		/**
		 * The Provider's JWK Set endpoint.
		 */
		private String jwkSetEndpoint;

		/**
		 * The Provider's OAuth 2.0 Token Revocation endpoint.
		 */
		private String tokenRevocationEndpoint;

		/**
		 * The Provider's OAuth 2.0 Token Introspection endpoint.
		 */
		private String tokenIntrospectionEndpoint;

		/**
		 * The Provider's OpenID Connect 1.0 Client Registration endpoint.
		 */
		private String oidcClientRegistrationEndpoint;

		/**
		 * The Provider's OpenID Connect 1.0 UserInfo endpoint.
		 */
		private String oidcUserInfoEndpoint;

		/**
		 * Additional settings.
		 */
		private Map<String, Object> additionalSettings = new HashMap<>();

		public String getIssuer() {
			return issuer;
		}

		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}

		public String getAuthorizationEndpoint() {
			return authorizationEndpoint;
		}

		public void setAuthorizationEndpoint(String authorizationEndpoint) {
			this.authorizationEndpoint = authorizationEndpoint;
		}

		public String getTokenEndpoint() {
			return tokenEndpoint;
		}

		public void setTokenEndpoint(String tokenEndpoint) {
			this.tokenEndpoint = tokenEndpoint;
		}

		public String getJwkSetEndpoint() {
			return jwkSetEndpoint;
		}

		public void setJwkSetEndpoint(String jwkSetEndpoint) {
			this.jwkSetEndpoint = jwkSetEndpoint;
		}

		public String getTokenRevocationEndpoint() {
			return tokenRevocationEndpoint;
		}

		public void setTokenRevocationEndpoint(String tokenRevocationEndpoint) {
			this.tokenRevocationEndpoint = tokenRevocationEndpoint;
		}

		public String getTokenIntrospectionEndpoint() {
			return tokenIntrospectionEndpoint;
		}

		public void setTokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
			this.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint;
		}

		public String getOidcClientRegistrationEndpoint() {
			return oidcClientRegistrationEndpoint;
		}

		public void setOidcClientRegistrationEndpoint(String oidcClientRegistrationEndpoint) {
			this.oidcClientRegistrationEndpoint = oidcClientRegistrationEndpoint;
		}

		public String getOidcUserInfoEndpoint() {
			return oidcUserInfoEndpoint;
		}

		public void setOidcUserInfoEndpoint(String oidcUserInfoEndpoint) {
			this.oidcUserInfoEndpoint = oidcUserInfoEndpoint;
		}

		public Map<String, Object> getAdditionalSettings() {
			return additionalSettings;
		}

		public void setAdditionalSettings(Map<String, Object> additionalSettings) {
			this.additionalSettings = additionalSettings;
		}

	}

}
