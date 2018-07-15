+++
date = 2018-07-05
publishDate = 2018-07-05
title = "Configuring Authorization with Reactive Spring Security 5"
description = "It takes just a few minutes to bring a compromised system to it's knees. Help fight this by securing your application with Spring Security"
toc = true
categories = ["spring","security","reactive"]
tags = ["demo","spring","webflux","appsec"]
+++

# Configuring Authorization against a Webflux App

Effective security can insulate our applications from ill effects of malicious, and accidental intent in many aspects of programming. Things like network security can only go so far in isolating harm to distributed computing applications. Prevent malicious hackers from gaining access to your systems by ensuring the tools meet the standards for your appcation.

[Spring Security WebFlux](https://docs.spring.io/spring-security/site/docs/5.0.6.RELEASE/reference/htmlsingle/) is the framework that lets us declare security constructs to our ordinary [WebFlux](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html)applications. This is similar to classical Spring Security and [WebMVC](https://docs.spring.io/spring-framework/docs/3.2.x/spring-framework-reference/html/mvc.html)  with the major difference being the use of functional and reactive techniques.

## Getting Started

To get started, one may use start.spring.io, or just ensure the following dependencies are configured to the project going forward:

* [WebFlux](https://docs.spring.io/spring/docs/5.0.0.BUILD-SNAPSHOT/spring-framework-reference/html/web-reactive.html)
* [Reactive Security 5](https://spring.io/blog/2017/10/04/spring-tips-reactive-spring-security)
* [lombok](https://projectlombok.org)

Next, lets briefly look at how this framework puts things together. We can compose our sample app throughout this article while highlighting common and often visited architectural pieces.

## Configuring Authorization Components

How does Spring Security Webflux let us describe our security details?

[ServerHttpSecurity](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html) surfaces components for customizing security behaviour across our web-stack through a DSL-like, fluent API. [ServerHttpSecurity](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html) ultimately builds the state of a [SecurityWebFilterChain](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/SecurityWebFilterChain.html) which gets executed within the primary [WebFilter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/server/WebFilter.html).

Lets take a look at some of the components we'll use to setup security throughout a web request/response lifecycle, hence [ServerWebExchange](https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/server/ServerWebExchange.html). We are given a variety of specifications that let us decide on which part of the [ServerWebExchange](https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/server/ServerWebExchange.html) we can lock down.

|Component|ServerHttpSecurity method|handling use cases|
|-----|-----|-----|
|AuthorizeExchangeSpec|.authorizeExchange()|pathMatchers, RBAC, custom Authorization|
|HeadersSpec|.headers()|Cross Site Scriptiong, Strict Transport Security, cache-control, frame options, etc...  |
|CsrfSpec|.csrf()|setup handler and token repository|
|ExceptionHandlingSpec|.exceptionHandling()|handler for authentication entry point and denial|
|HttpBasicSpec|.httpBasic()|custom AuthenticationManager, authentication context config|
|RequestCacheSpec|.requestCache()|handle saving httpRequest prior to authentication|
|FormLoginSpec|.formLogin()|set login page, authentication behaviour on success/deny|
|LogoutSpec|.logout()|set logout page and handler|

NOTE: All of the above components may be disabled using it's .disable() method!

### Authorization Configuration

Using the [AuthorizeExchangeSpec](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.AuthorizeExchangeSpec.html) by invoking `authorizeExchange()`, one can issue URI [PathPattern](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/util/matcher/PathPatternParserServerWebExchangeMatcher.html)'s that will match Access Control rules to paths on the service route.

For example, `hasRole()` method is a shorthand for `hasAuthority()` method where the user's [GrantedAuthority](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/core/GrantedAuthority.html) (aka privilege) is checked for specific values. The `hasRole()` requires each authority be prefixed with 'ROLE_'.

Finally, there is the `access()` method that takes a anonymous or otherwise custom implementation of [ReactiveAuthorizationManager](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authorization/ReactiveAuthorizationManager.html). This is useful for in-house authorization implementations.

### CSRF Configuration

Another component for when configuring SecurityWebFilterChain is the [CsrfSpec](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.CsrfSpec.html) enabled by calling `csrf()` method.  This lets us configure [CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet) tokens and handlers, or exclude CSRF entirely.

To configure CSRF metadata behaviour, create a bean of type [ServerCsrfTokenRepository](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/csrf/ServerCsrfTokenRepository.html) and set header and/or parameter attrubte names as shown.

SecurityConfiguration.java:

    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
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
                .pathMatchers("/who")
                .hasRole("USER")
                .pathMatchers("/primes")
                .hasAuthority("ROLE_USER")
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

Additionally the `and()` and `or()` and `disable()` methods lets us build another component's filter on the filter chain. In this case, we give our customized [ServerCsrfTokenRepository](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/csrf/ServerCsrfTokenRepository.html), and configure HTTP Basic. Calling `build()` returns the completed [SecurityWebFilterChain](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/SecurityWebFilterChain.html).

# Review

This brief overview should set you up for engaging the ServerHttpSecurity components. Following it's fluent API is a breeze once we get to know the components that we visit.
