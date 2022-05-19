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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.annotation.Role;

/**
 * @author Steve Riesenberg
 * @since 0.3.1
 */
public class JwkSourceConfiguration {

	@Configuration
	@Profile("default")
	public static class Default {

		@Bean
		@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
		JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			// @formatter:off
			RSAKey rsaKey = new RSAKey.Builder(publicKey)
					.privateKey(privateKey)
					.keyID(UUID.randomUUID().toString())
					.build();
			// @formatter:on
			JWKSet jwkSet = new JWKSet(rsaKey);
			return new ImmutableJWKSet<>(jwkSet);
		}

		@Bean
		@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
		public KeyPair loadRsaKey(
				@Value("${jwt.public.key}") RSAPublicKey publicKey,
				@Value("${jwt.private.key}") RSAPrivateKey privateKey
		) {
			return new KeyPair(publicKey, privateKey);
		}

	}

	@Configuration
	@Profile("keyGen")
	public static class KeyGen {

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			KeyPair keyPair = generateRsaKey();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			// @formatter:off
			RSAKey rsaKey = new RSAKey.Builder(publicKey)
					.privateKey(privateKey)
					.keyID(UUID.randomUUID().toString())
					.build();
			// @formatter:on
			JWKSet jwkSet = new JWKSet(rsaKey);
			return new ImmutableJWKSet<>(jwkSet);
		}

		private static KeyPair generateRsaKey() {
			KeyPair keyPair;
			try {
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
				keyPairGenerator.initialize(2048);
				keyPair = keyPairGenerator.generateKeyPair();
			}
			catch (Exception ex) {
				throw new IllegalStateException(ex);
			}
			System.out.println("Generated key pair:");
			System.out.println();
			System.out.println("-----BEGIN PUBLIC KEY-----\n" + format(keyPair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
			System.out.println();
			System.out.println("-----BEGIN PRIVATE KEY-----\n" + format(keyPair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----");
			System.out.println();
			return keyPair;
		}

		private static String format(byte[] key) {
			String encodedKey = new String(Base64.getEncoder().encode(key));
			return String.join("\n", encodedKey.split("(?<=\\G.{64})"));
		}

	}

}
