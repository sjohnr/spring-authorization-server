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

package sample.model;

import java.util.List;

/**
 * @author Steve Riesenberg
 */
public class UserInfo {

    private final String email;
    private final String name;
    private final String profileImage;
    private final String password;
    private final String securityQuestion;
    private final List<String> secrets;
    private final String answer;

    public UserInfo(String email, String name, String profileImage, String password, String securityQuestion, List<String> secrets, String answer) {
        this.email = email;
        this.name = name;
        this.profileImage = profileImage;
        this.password = password;
        this.securityQuestion = securityQuestion;
        this.secrets = secrets;
        this.answer = answer;
    }

    public UserInfo(UserInfo userInfo) {
        this(userInfo.getEmail(), userInfo.getName(), userInfo.getProfileImage(), userInfo.getPassword(), userInfo.getSecurityQuestion(), userInfo.getSecrets(), userInfo.getAnswer());
    }

    public String getEmail() {
        return this.email;
    }

    public String getName() {
        return this.name;
    }

    public String getProfileImage() {
        return this.profileImage;
    }

    public String getPassword() {
        return this.password;
    }

    public String getSecurityQuestion() {
        return this.securityQuestion;
    }

    public List<String> getSecrets() {
        return this.secrets;
    }

    public String getAnswer() {
        return answer;
    }

    @Override
    public String toString() {
        return "UserInfo{" +
            "email='" + email + '\'' +
            ", name='" + name + '\'' +
            ", profileImage='" + profileImage + '\'' +
            ", securityQuestion='" + securityQuestion + '\'' +
            '}';
    }

}
