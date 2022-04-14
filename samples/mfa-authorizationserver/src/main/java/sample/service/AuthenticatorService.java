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

package sample.service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.stereotype.Service;

/**
 * @author Steve Riesenberg
 */
@Service
public class AuthenticatorService {

    private final BytesEncryptor bytesEncryptor;

    public AuthenticatorService(BytesEncryptor bytesEncryptor) {
        this.bytesEncryptor = bytesEncryptor;
    }

    public boolean check(String key, String code) {
        try {
            String secret = new String(this.bytesEncryptor.decrypt(Hex.decode(key)), StandardCharsets.UTF_8);
            return TimeBasedOneTimePasswordUtil.validateCurrentNumber(secret, Integer.parseInt(code), 10000);
        }
        catch (IllegalArgumentException ex) {
            return false;
        }
        catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    public String generateSecret() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return new String(Hex.encode(this.bytesEncryptor.encrypt(bytes)));
    }

}
