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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * @author Steve Riesenberg
 */
public class MultiFactorAuthentication extends AbstractAuthenticationToken {

    private final Authentication primaryAuthentication;
    private final boolean authenticated;

    public MultiFactorAuthentication(Authentication primaryAuthentication, String authority, boolean authenticated) {
        super(AuthorityUtils.createAuthorityList(authority));
        this.primaryAuthentication = primaryAuthentication;
        this.authenticated = authenticated;
    }

    @Override
    public Object getPrincipal() {
        return this.primaryAuthentication.getPrincipal();
    }

    @Override
    public Object getCredentials() {
        return this.primaryAuthentication.getCredentials();
    }

    @Override
    public void eraseCredentials() {
        if (this.primaryAuthentication instanceof CredentialsContainer) {
            ((CredentialsContainer) this.primaryAuthentication).eraseCredentials();
        }
    }

    @Override
    public boolean isAuthenticated() {
        return this.authenticated;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        throw new UnsupportedOperationException();
    }

    public Authentication getPrimaryAuthentication() {
        return this.primaryAuthentication;
    }

}
