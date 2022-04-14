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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.oauth2.core.authentication.OAuth2AuthenticationValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.web.access.ExceptionTranslationFilter;

/**
 * @author Steve Riesenberg
 */
public final class ObjectPostProcessors {

    private ObjectPostProcessors() {
    }

    public static ObjectPostProcessor<ExceptionTranslationFilter> multiFactorTrustResolver() {
        return new ObjectPostProcessor<>() {
            @Override
            public <O extends ExceptionTranslationFilter> O postProcess(O exceptionTranslationFilter) {
                exceptionTranslationFilter.setAuthenticationTrustResolver(new MultiFactorTrustResolver());
                return exceptionTranslationFilter;
            }
        };
    }

    public static ObjectPostProcessor<OAuth2AuthorizationCodeRequestAuthenticationProvider> authorizationCodeRequest() {
        return new ObjectPostProcessor<>() {
            @Override
            public <O extends OAuth2AuthorizationCodeRequestAuthenticationProvider> O postProcess(O authenticationProvider) {
                Map<String, OAuth2AuthenticationValidator> authenticationValidators = new HashMap<>();
                authenticationValidators.put(OAuth2ParameterNames.REDIRECT_URI, new RedirectUriValidator());
                authenticationProvider.setAuthenticationValidatorResolver(authenticationValidators::get);
                return authenticationProvider;
            }
        };
    }

}
