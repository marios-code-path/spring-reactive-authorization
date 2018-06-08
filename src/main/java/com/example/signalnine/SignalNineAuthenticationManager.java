package com.example.signalnine;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;

import java.util.Collection;

//@Component
@Slf4j
class SignalNineAuthenticationManager implements ReactiveAuthenticationManager {
    private final AccountService accountService;

    SignalNineAuthenticationManager(AccountService service) {
        this.accountService = service;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        UsernamePasswordAuthenticationToken auth = UsernamePasswordAuthenticationToken.class.cast(authentication);

// Authenticate as anonymous when user/password is not present.
// Perhaps signal if web security supports this (@EnableAnonymous, etc...)
        if ((auth.getName() == null || auth.getName().isEmpty()) &&
                (auth.getCredentials() == null || auth.getCredentials().toString().isEmpty())) {
            Tuple2<SignalUser, Collection<GrantedAuthority>> anon = null;
            return Mono.just(new SignalAuthenticationToken(anon.getT2(), anon.getT1()));
        }

// Validates any password, but must have username in users collection
        if (auth.getCredentials().toString().isEmpty())
            throw new UsernameNotFoundException("Access Denied");

// User search would end up handled by the UserDetails Service
        SignalUser authUser = null;

        SignalAuthenticationToken token =
                new SignalAuthenticationToken(null, authUser);

        token.setAuthenticated(true);

        return Mono.just(token);
    }
}