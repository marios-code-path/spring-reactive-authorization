package com.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;


@Configuration
public class UserDetailServiceBeans {

    private static final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    private static UserDetails user(String u, String... roles) {
        return User.builder()
                .username(u)
                .password("password")
                .passwordEncoder(encoder::encode)
                .roles(roles)
                .build();
    }

    private static final Collection<UserDetails> users = new ArrayList<>(
            Arrays.asList(
                    user("thor", "ADMIN"),
                    user("loki", "USER"),
                    user("zeus", "ADMIN", "USER")
            ));

    @Bean
    public MapReactiveUserDetailsService mapReactiveUserDetailsService() {
        return new MapReactiveUserDetailsService(users);
    }

}