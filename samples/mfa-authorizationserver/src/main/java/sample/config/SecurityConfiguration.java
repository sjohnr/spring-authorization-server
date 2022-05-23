/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import sample.security.MultiFactorAuthenticationHandler;
import sample.security.ObjectPostProcessors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Spring Security configuration.
 *
 * @author Steve Riesenberg
 */
@Configuration
public class SecurityConfiguration {

    @Bean
    @Order(1)
    protected SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        authorizationServerConfigurer.withObjectPostProcessor(ObjectPostProcessors.authorizationCodeRequest());
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        // @formatter:off
        http
            .requestMatcher(endpointsMatcher)
            .authorizeRequests(authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
            .apply(authorizationServerConfigurer);
        // @formatter:on

        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    @Order(2)
    protected SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .authorizeRequests((authorizeRequests) ->
                authorizeRequests
                    .antMatchers("/assets/**", "/webjars/**", "/login").permitAll()
                    .antMatchers("/authenticator").hasAuthority("MFA_REQUIRED")
                    .antMatchers("/security-question").hasAuthority("SECURITY_QUESTION_REQUIRED")
                    .anyRequest().hasRole("USER")
            )
            .formLogin((formLogin) ->
                formLogin
                    .loginPage("/login")
                    .successHandler(new MultiFactorAuthenticationHandler("/authenticator", "MFA_REQUIRED"))
                    .failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"))
            )
            .exceptionHandling((exceptionHandling) ->
                exceptionHandling
                    .withObjectPostProcessor(ObjectPostProcessors.multiFactorTrustResolver())
            )
            .logout((logout) -> logout.logoutSuccessUrl("/"));
        // @formatter:on

        return http.build();
    }

//    @Bean
//    public KeyGenerator keyGenerator() throws NoSuchAlgorithmException {
//        KeyGenerator generator = KeyGenerator.getInstance("AES");
//        generator.init(128);
//        return generator;
//    }

    @Bean
    public BytesEncryptor bytesEncryptor(/*KeyGenerator keyGenerator, */@Value("${enc.secret.key}") String secret) {
//        SecretKey secretKey = keyGenerator.generateKey();
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(secret.trim()), "AES");
        BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(12);
        return new AesBytesEncryptor(secretKey, ivGenerator, AesBytesEncryptor.CipherAlgorithm.GCM);
    }

    private static String format(byte[] key) {
        String encodedKey = new String(Base64.getEncoder().encode(key));
        return String.join("\n", encodedKey.split("(?<=\\G.{64})"));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new SavedRequestAwareAuthenticationSuccessHandler();
    }

}
