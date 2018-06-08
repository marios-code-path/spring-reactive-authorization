package com.example.signalnine;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import java.util.*;

@Service
public class UserService {
    final SignalUser anonymousUser = new SignalUser(0L, "ANONYMOUS");

    //!! Instrument a UserDetails Service to handle this bit of logic:
    Collection<SignalUser> users = Arrays.asList(
            new SignalUser(1L, "Mario"),
            new SignalUser(2L, "Luigi"),
            new SignalUser(3L, "Admin")
    );

    Map<Long, Collection<GrantedAuthority>> authoritiesMap = new TreeMap() {{
        put(1L, Collections.singletonList((GrantedAuthority) () -> "ROLE_USER"));
        put(2L, Collections.singletonList((GrantedAuthority) () -> "ROLE_USER"));
        put(3L, Collections.singletonList((GrantedAuthority) () -> "ROLE_ADMIN"));
        put(0L, Collections.singletonList((GrantedAuthority) () -> "ROLE_ANONYMOUS"));
    }};

    public Tuple2<SignalUser, Collection<GrantedAuthority>> getUserById(Long id) {
        SignalUser user =  users
                .stream()
                .filter(u -> u.getId().equals(id))
                .findFirst()
                .orElse(anonymousUser);
        Collection<GrantedAuthority> authorities = authoritiesMap.get(user.getId());
        return Tuples.of(user, authorities);
    }
}
