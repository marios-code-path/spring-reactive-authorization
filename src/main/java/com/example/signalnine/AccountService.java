package com.example.signalnine;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.TreeMap;

@Service
@Slf4j
public class AccountService implements ReactiveUserDetailsService {
    private final PasswordEncoder pw = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    Map<String, SignalUser> userAccounts = new TreeMap() {{
        put("mario", new SignalUser(
                new SignalUser.Account("mario", pw.encode("password"), true),
                "ROLE_USER")
        );
        put("luigi", new SignalUser(
                new SignalUser.Account(
                        "luigi", pw.encode("password"), true),
                "ROLE_ADMIN,ROLE_USER")
        );
    }};

    public Flux<String> getAccountNames() {
        return Flux.fromStream(this.userAccounts.keySet().stream());
    }
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        SignalUser user = userAccounts.getOrDefault(username, null);
        return user == null ? Mono.empty() : Mono.just(user);
    }
}