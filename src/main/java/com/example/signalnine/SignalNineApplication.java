package com.example.signalnine;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.server.*;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.time.Duration;

@EnableWebFlux
@SpringBootApplication
public class SignalNineApplication {

    public static void main(String[] args) {
        SpringApplication.run(SignalNineApplication.class); //.getBeanFactory().getBean(NettyContext.class).onClose().block();
    }
}


@org.springframework.web.bind.annotation.RestController
@Slf4j
class RestController {

    Mono<ServerResponse> handleNames(ServerRequest request) {
        return ServerResponse.ok().body(Mono.zip(request.principal(), Mono.just(" HERE"),
                (p, s) -> p.getName() + s), String.class);
    }

    @Bean
    RouterFunction<?> routes() {
        return RouterFunctions.route(RequestPredicates.GET("/names"), this::handleNames);
    }

    // TODO this is a kludge, or is it?
    @GetMapping(value = "/primes", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent> primeFlux(Mono<Principal> principal) {
        return Flux.interval(Duration.ofMillis(250))
                .zipWith(principal.repeat(), //.or(Mono.just(ANONYMOUS_USER))repeat(),
                        (n, user) -> ServerSentEvent.builder()
                                .data(user.getName() + " " + (n + (is_prime(n) ? "!" : "")))
                                .id(n + "-id")
                                .event("NUMBER")
                                .build()
                );
    }

    // brute-force search :p
    boolean is_prime(long num) {
        if (num <= 1) return false;
        if (num % 2 == 0 && num > 2) return false;
        for (int i = 3; i < num / 2; i += 2) {
            if (num % i == 0)
                return false;
        }
        return true;
    }
}

@Component
@Slf4j
class ExampleWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange serverWebExchange,
                             WebFilterChain webFilterChain) {
        serverWebExchange.getPrincipal().doOnNext(p -> serverWebExchange.getAttributes().putIfAbsent("user", p)).repeat();
        return webFilterChain.filter(serverWebExchange);
    }
}

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Slf4j
class SecurityConfig {

    @Bean
    public AnonymousAuthenticationFilter anonFilter() {
        return new AnonymousAuthenticationFilter("example");
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.authorizeExchange()
                .pathMatchers("/primes")
                .access((mono, context) -> mono
                        .map(auth -> UserDetails.class.cast(auth.getPrincipal()))
                        .map(u -> {log.info("Seen a primes request for" + u.getUsername()); return true;})//u.isEnabled() || u.getUsername().endsWith("mgray"))
                        .map(AuthorizationDecision::new)
                )
                .anyExchange()
                .permitAll()
                .and()
                .httpBasic()
                .and()
                .build();
    }

    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("mgray")
                .password("password")
                .roles("USER")
                .build();
        return new MapReactiveUserDetailsService(user);
    }

}
