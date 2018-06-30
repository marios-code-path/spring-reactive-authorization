package com.example;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Slf4j
@Configuration
public class SecurityConfiguration {

    @Bean
    public ServerCsrfTokenRepository csrfTokenRepository() {
        WebSessionServerCsrfTokenRepository repository =
            new WebSessionServerCsrfTokenRepository();
        repository.setHeaderName("X-CSRF-TK");

        return repository;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        return http
                .authorizeExchange()
                .pathMatchers("/who*")
                .hasRole("USER")
                .pathMatchers("/primes")
                .hasRole("USER")
                .pathMatchers("/admin")
                .access((mono, context) -> mono
                        .map(auth -> auth.getAuthorities().stream()
                                .filter(e -> e.getAuthority().equals("ROLE_ADMIN"))
                                .count() > 0)
                        .map(AuthorizationDecision::new)
                )
                .and()
                .csrf()
                    .csrfTokenRepository(csrfTokenRepository())
                    .and()
                .httpBasic()
                .and()
                .build();
    }
}
