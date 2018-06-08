package com.example.signalnine;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;


@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Slf4j
@Configuration
public class SecurityConfiguration {
    private final SignalNineAuthenticationManager authenticationManager;

    public SecurityConfiguration(SignalNineAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http.authenticationManager(this.authenticationManager);

        return http
                .authorizeExchange()
                .pathMatchers("/primes")
                .hasRole("USER")
                .pathMatchers("/zero")
                .permitAll()
                .pathMatchers("/special")
                .access((mono, context) -> mono
                        .map(n -> SignalUser.class.cast(n.getPrincipal())
                                .getAuthorities().stream()
                                .map(e -> e.getAuthority().equals("ROLE_ADMIN"))
                                .count() > 0)
                        .map(AuthorizationDecision::new)
                )
                .pathMatchers("/users")
                .hasAuthority("ADMIN")
                .and()
                .httpBasic()
                .and()
                .build();
    }
}



