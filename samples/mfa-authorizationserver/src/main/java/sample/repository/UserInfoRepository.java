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

package sample.repository;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;

import sample.model.UserInfo;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author Steve Riesenberg
 */
@Component
public class UserInfoRepository {

    private final Map<String, UserInfo> users = new HashMap<>();

    public UserInfoRepository(PasswordEncoder passwordEncoder, BytesEncryptor bytesEncryptor) {
        this.passwordEncoder = passwordEncoder;
        this.bytesEncryptor = bytesEncryptor;
    }

    private final PasswordEncoder passwordEncoder;
    private final BytesEncryptor bytesEncryptor;

    @PostConstruct
    public void initialize() {
        List<UserInfo> users = List.of(
            userInfo("user@spring.io", "Spring User", "/assets/img/profile/user.jpg"),
            userInfo("admin@spring.io", "Admin User", "/assets/img/profile/admin.jpg")
        );
        users.forEach(userInfo -> this.users.put(userInfo.getEmail(), userInfo));
    }

    private UserInfo userInfo(String email, String name, String profileImage) {
        // Simulate what would be stored in the database
        String encodedPassword = this.passwordEncoder.encode("password");
        String encodedAnswer = this.passwordEncoder.encode("pepperoni");
        String base32Secret = "QDWSM3OYBPGTEVSPB5FKVDM3CSNCWHVK";
        // String hexSecret = "80ed266dd80bcd32564f0f4aaa8d9b149a2b1eaa";
        String encryptedSecret = new String(Hex.encode(this.bytesEncryptor.encrypt(base32Secret.getBytes(StandardCharsets.UTF_8))));
        return new UserInfo(email, name, profileImage, encodedPassword, "What is your favorite pizza topping?", Collections.singletonList(encryptedSecret), encodedAnswer);
    }

    public UserInfo findUserByEmail(String email) {
        return users.get(email);
    }

}
