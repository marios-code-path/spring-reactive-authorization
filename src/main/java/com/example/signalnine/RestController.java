package com.example.signalnine;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.server.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.time.Duration;

@org.springframework.web.bind.annotation.RestController
@Slf4j
public class RestController {

    Mono<ServerResponse> handleSpecialRoute(ServerRequest request) {
        return ServerResponse
                .ok()
                .body(request.principal().repeat().zipWith(
                        Mono.just("I am a user named: "),
                        (p, s) -> s + p.getName()), String.class);
    }

    Mono<ServerResponse> handleNameRequest(ServerRequest request) {
        return ServerResponse
                .ok() // how to set the anonymous user BEFORE the request sees the principal?
                .body(request.principal().repeat().zipWith(
                        Mono.just("HERE is "),
                        (p, s) -> s + p.getName()), String.class);
    }

    @Bean
    RouterFunction<?> routes() {
        return RouterFunctions.route(RequestPredicates.GET("/names"), this::handleNameRequest)
                .andRoute(RequestPredicates.GET("/special"), this::handleSpecialRoute);
    }

    // TODO this is a kludge, or is it?
    @GetMapping(value = "/primes", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent> primeFlux(Mono<Principal> principal) {
        return Flux.interval(Duration.ofMillis(250))
                .zipWith(principal.repeat(),
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