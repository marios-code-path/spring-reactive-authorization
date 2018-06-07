package com.example.signalnine;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Slf4j
public class SecurityConfiguration {
    private final AuthenticationManager authenticationManager;

    public SecurityConfiguration(AuthenticationManager authMan) {
        this.authenticationManager = authMan;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http.authenticationManager(authenticationManager);

        return http.authorizeExchange()
                .pathMatchers("/primes")
                .access((mono, context) -> mono
                        .map(auth -> UserDetails.class.cast(auth.getPrincipal()))
                        .map(u -> !u.getUsername().isEmpty())
                        .map(AuthorizationDecision::new)
                )
                .and()
                .authorizeExchange()
                .pathMatchers("/users")
                .hasRole("ADMIN")
                .and()
                .httpBasic()
                .and()
                .build();
    }
}


class SignalAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final SignalAuthenticationToken auth = SignalAuthenticationToken.class.cast(authentication);
        final SignalUser anonymousUser = new SignalUser(0L, "ANONYMOUS");

        //!! Instrument a UserDetails Service to handle this bit of logic:
        Collection<SignalUser> users = Arrays.asList(
                new SignalUser(1L, "Mario"),
                new SignalUser(2L, "Luigi"),
                new SignalUser(3L, "Admin")
        );

        Map<Long, Collection<GrantedAuthority>> authoritiesMap = new TreeMap<>();
        authoritiesMap.put(1L, Arrays.asList((GrantedAuthority) () -> "ROLE_USER"));
        authoritiesMap.put(2L, Arrays.asList((GrantedAuthority) () -> "ROLE_USER"));
        authoritiesMap.put(3L, Arrays.asList((GrantedAuthority) () -> "ROLE_ADMIN"));
        authoritiesMap.put(0L, Arrays.asList((GrantedAuthority) () -> "ROLE_ANONYMOUS"));

// Authenticate as anonymous when user/password is not present.
// Perhaps signal if web security supports this (@EnableAnonymous, etc...)
        if ((auth.getName() == null || auth.getName().isEmpty()) &&
                (auth.getCredentials() == null || auth.getCredentials().toString().isEmpty()))
            return new SignalAuthenticationToken(authoritiesMap.get(anonymousUser.getId()), anonymousUser);

// Validates any password, but must have username in users collection
        if (auth.getCredentials().toString().isEmpty() ||
                !users.stream().anyMatch(p -> p.getUsername().equalsIgnoreCase(auth.getName())))
            throw new UsernameNotFoundException("Access Denied");

// User search would end up handled by the UerDetails Service
        final SignalUser authUser = users.stream()
                .filter(p -> p.getUsername().equals(auth.getName()))
                .findFirst()
                .orElse(anonymousUser);

        return new SignalAuthenticationToken(authoritiesMap.get(authUser), authUser);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SignalAuthenticationToken.class.equals(authentication);
    }
}

@Component
@Slf4j
class AuthenticationManager implements ReactiveAuthenticationManager {

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        // JwtAuthenticationToken is my custom token.
        if (authentication instanceof SignalAuthenticationToken) {
            log.info("User login: " + SignalAuthenticationToken.class.cast(authentication).getName());
            authentication.setAuthenticated(true);
        }
        return Mono.just(authentication);
    }
}

