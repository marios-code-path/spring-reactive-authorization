package com.example;

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

    Map<String, User> userAccounts = new TreeMap();

    public AccountService() {
        userAccounts.put("mario", new User(
                new User.Account("mario", pw.encode("password"), true),
                "ROLE_USER")
        );
        userAccounts.put("luigi", new User(
                new User.Account(
                        "luigi", pw.encode("password"), true),
                "ROLE_ADMIN,ROLE_USER")
        );
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        User user = userAccounts.getOrDefault(username, null);
        return user == null ? Mono.empty() : Mono.just(user);
    }
}