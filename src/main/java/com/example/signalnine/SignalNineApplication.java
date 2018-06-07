package com.example.signalnine;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.reactive.config.EnableWebFlux;

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

