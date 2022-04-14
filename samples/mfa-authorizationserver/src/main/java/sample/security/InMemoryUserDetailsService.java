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

package sample.security;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import sample.model.UserInfo;
import sample.repository.UserInfoRepository;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * @author Steve Riesenberg
 */
@Component
public class InMemoryUserDetailsService implements UserDetailsService {

    private static final Set<String> ADMIN_USERS = Set.of("admin@spring.io");

    public static final List<GrantedAuthority> ADMIN_AUTHORITIES =
        Collections.unmodifiableList(AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN"));

    public static final List<GrantedAuthority> USER_AUTHORITIES =
        Collections.unmodifiableList(AuthorityUtils.createAuthorityList("ROLE_USER"));

    private final UserInfoRepository userInfoRepository;

    public InMemoryUserDetailsService(UserInfoRepository userInfoRepository) {
        this.userInfoRepository = userInfoRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return findUserByEmail(username.contains("@") ? username : username + "@spring.io");
    }

    private InMemoryUserDetails findUserByEmail(String email) {
        UserInfo userInfo = this.userInfoRepository.findUserByEmail(email);
        if (userInfo == null) {
            throw new UsernameNotFoundException("User " + email + " not found");
        }

        List<GrantedAuthority> grantedAuthorities;
        if (ADMIN_USERS.contains(email)) {
            grantedAuthorities = ADMIN_AUTHORITIES;
        } else {
            grantedAuthorities = USER_AUTHORITIES;
        }

        return new InMemoryUserDetails(userInfo, grantedAuthorities);
    }

    private static final class InMemoryUserDetails extends UserInfo implements UserDetails {

        private final List<GrantedAuthority> authorities;

        public InMemoryUserDetails(UserInfo userInfo, List<GrantedAuthority> authorities) {
            super(userInfo);
            this.authorities = authorities;
        }

        @Override
        public String getUsername() {
            return getEmail();
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.authorities;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public String toString() {
            return "InMemoryUserDetails{" +
                "email='" + getEmail() + '\'' +
                ", name='" + getName() + '\'' +
                ", profileImage='" + getProfileImage() + '\'' +
                ", authorities=" + authorities +
                '}';
        }
    }

}
