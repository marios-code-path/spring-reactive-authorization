package com.example;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;

import java.util.*;


@Configuration
public class UserDetailServiceBeans {

    private static final PasswordEncoder pw = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    private static UserDetails user(String u, String... roles) {
        return new ExampleUser(new ExampleUser.Account(u, pw.encode("password"), true),
                roles);
    }

    private static final Collection<UserDetails> users = new ArrayList<>(
            Arrays.asList(
                    user("rjohnson", "ROLE_ADMIN"),
                    user("cwalls", "ROLE_USER"),
                    user("jlong", "ROLE_USER"),
                    user("rwinch", "ROLE_ADMIN", "ROLE_USER"),
                    user("mgray", "ROLE_ADMIN", "ROLE_USER")
            ));

    @Bean
    @Profile("map-reactive")
    public MapReactiveUserDetailsService mapReactiveUserDetailsService() {
        return new MapReactiveUserDetailsService(users);
    }

    @Bean
    @Profile("custom")
    public ExampleUserDetailService customUserDetailService() {
        return new ExampleUserDetailService(users);
    }

    @Slf4j
    static class ExampleUserDetailService implements ReactiveUserDetailsService {
        Map<String, UserDetails> userAccounts = new TreeMap<>();

        public ExampleUserDetailService(Collection<UserDetails> userCollection) {
            userCollection.forEach(u ->
                    userAccounts.put(u.getUsername(), u)
            );
        }

        @Override
        public Mono<UserDetails> findByUsername(String username) {
            UserDetails user = userAccounts.getOrDefault(username, null);
            return user == null ? Mono.empty() : Mono.just(user);
        }

    }

}