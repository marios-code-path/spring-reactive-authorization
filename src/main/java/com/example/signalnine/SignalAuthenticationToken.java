package com.example.signalnine;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

class SignalAuthenticationToken extends AbstractAuthenticationToken {
    private final SignalUser user;

    public SignalAuthenticationToken(Collection<? extends GrantedAuthority> authorities, SignalUser user) {
        super(authorities);
        this.user = user;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.user;
    }
}
