package com.example.signalnine;

import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.TreeMap;

@Service
public class AccountService implements ReactiveUserDetailsService {
    private final PasswordEncoder pw = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    Map<String, SignalUser> userAccounts = new TreeMap() {{
        put("mario", new SignalUser(
                new SignalUser.Account(
                        "mario", pw.encode("password")),
                "ROLE_USER",
                true)
        );
        put("admin", new SignalUser(
                new SignalUser.Account(
                        "luigi", pw.encode("password")),
                "ROLE_ADMIN,ROLE_USER",
                true)
        );
    }};

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.just(userAccounts.get(username));
    }
}
