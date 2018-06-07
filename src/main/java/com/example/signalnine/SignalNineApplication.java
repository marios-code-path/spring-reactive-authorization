package com.example.signalnine;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.reactive.config.EnableWebFlux;

import javax.security.auth.Subject;
import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;

/**
 * objective to this demo:
 * <p>
 * Demonstrate consumption of n client-credential-protected service
 * Demonstrate creation of a client-credential protected resource
 * Demonstrate different security scope ( method-security, endpoint-security )
 * Setup for demonstrating Propigation of security rules to additional hosts.
 * <p>
 * <p>
 * It should be simple to lock down a typical req->res service using Spring Security
 * Sure we must setup Authority, and the amount of boilerplate is much lower than with
 * earlier incarnations.  I feel this current version is 'unfinished' possibly too much
 * code to make simple things ( client-credential) work. This follows for both Client and
 * Service configurations.
 */
@EnableWebFlux
@SpringBootApplication
public class SignalNineApplication {
    public static void main(String[] args) {
        SpringApplication.run(SignalNineApplication.class);
    }
}

@NoArgsConstructor
@AllArgsConstructor
@Data
class SignalUser implements Principal, Serializable {
    Long id;
    String username;

    @Override
    public String getName() {
        return username;
    }

    @Override   // asks: is this a lowest-level User Principal ?
    public boolean implies(Subject subject) {
        return true;
    }
}

class SignalAuthenticationToken extends AbstractAuthenticationToken {
    private final SignalUser user;

    public SignalAuthenticationToken(Collection<? extends GrantedAuthority> authorities, SignalUser user) {
        super(authorities);
        this.user = user;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.user;
    }
}

