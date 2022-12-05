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
package sample;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class JwtBearerGrantTests {
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();

	@Autowired
	private MockMvc mvc;

	@Test
	public void exchangeAccessTokenUsingJwtBearerGrant() throws Exception {
		// Obtain access token using 'client_credentials' grant
		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "message.read message.write")
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						"messaging-client", "secret")))
				.andExpect(status().isOk())
				.andReturn();

		String accessToken = getAccessToken(mvcResult).getTokenValue();
		System.out.println("access token from 'client_credentials' grant -> " + accessToken);

		// Exchange access token using 'jwt-bearer' grant
		mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.JWT_BEARER.getValue())
				.param(OAuth2ParameterNames.ASSERTION, accessToken)
				.param(OAuth2ParameterNames.SCOPE, "message.read")
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						"messaging-client", "secret")))
				.andExpect(status().isOk())
				.andReturn();

		accessToken = getAccessToken(mvcResult).getTokenValue();
		System.out.println("access token from 'jwt-bearer' grant -> " + accessToken);
	}

	private static OAuth2AccessToken getAccessToken(MvcResult mvcResult) {
		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
		try {
			return accessTokenHttpResponseConverter.read(
					OAuth2AccessTokenResponse.class, httpResponse).getAccessToken();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static String encodeBasicAuth(String clientId, String secret) throws Exception {
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return new String(encodedBytes, StandardCharsets.UTF_8);
	}

}
