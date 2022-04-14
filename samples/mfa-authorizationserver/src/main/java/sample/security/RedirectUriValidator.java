/*
 * Copyright 2002-2022 the original author or authors.
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

package sample.security;

import java.util.Objects;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.core.authentication.OAuth2AuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

/**
 * @author Steve Riesenberg
 */
public class RedirectUriValidator implements OAuth2AuthenticationValidator {
    @Override
    public void validate(OAuth2AuthenticationContext authenticationContext) throws OAuth2AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authentication = authenticationContext.getAuthentication();
        RegisteredClient registeredClient = Objects.requireNonNull(authenticationContext.get(RegisteredClient.class));

        String redirectUri = authentication.getRedirectUri();
        if (StringUtils.hasText(redirectUri)) {
            boolean noneMatch = registeredClient.getRedirectUris().stream().noneMatch(redirectUri::equals);
            if (noneMatch) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "redirect_uri", "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1");
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authentication);
            }
        }
    }
}
