# Sample Spring Security WebFlux

This article discuses the Spring Security configuration for apps that want to also use
reactive WebFlux.

What was wrong with traditional security in Spring Web/MVC applications? 
Nothing - this new framework addition lets us expose and secure Web Components
using functional and reactive techniques. Whats more is we have a brand new way 
to express the fundamental routing logic, and request handling logic for each web 
request. 

## Getting Started

To get started, we can call 'start.spring.io' to generate a baseline app with the following dependencies:

 * [WebFlux](https://docs.spring.io/spring/docs/5.0.0.BUILD-SNAPSHOT/spring-framework-reference/html/web-reactive.html) 
 * [Reactive Security 5](https://spring.io/blog/2017/10/04/spring-tips-reactive-spring-security)
 * [lombok](https://projectlombok.org)
 
You can additionally download the baseline project from [start.spring.io](http://start.spring.io/starter.zip?type=maven-project&language=java&bootVersion=2.0.3.RELEASE&baseDir=security&groupId=com.example&artifactId=security&name=security&description=Demo+Reactive+Security+Project&packageName=com.example.security&packaging=jar&javaVersion=1.8&autocomplete=&generate-project=&style=security&style=lombok&style=webflux)

## Reactive Components Breakdown

The [ServerHttpSecurity](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html) 
is the reactive version for [HttpSecurity](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/config/annotation/web/builders/HttpSecurity.html) which allows us to program web-based security 
rules for specific web endpoints. This API harnesses [ServerWebExchangeMatcher](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/util/matcher/ServerWebExchangeMatcher.html)
to enforce security rules to our service paths. 

In particular, AuthorizationManager gets instantiated each time a decision has to be made. The pre-configured ones used in 'hasRole' and 'hasAuthority' is probably too coarse, thus we can administer our customized AuthorizationManager to check that a user has access to an endpoint as seen in the sample code below:

As an example:
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    @Configuration
    public class SecurityConfiguration {
        @Bean
        public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        return http
                .authorizeExchange()
                .pathMatchers("/who")
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
                .httpBasic()
                .and()
                .build();
        }

    }

## AuthenticationManager and WebFilter
By default, the reactive ServerHttpSecurity instance will configure an instance of
[ReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/ReactiveAuthenticationManager.html)
which is the reactive component for traditional [AuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/AuthenticationManager.html)
whose job it is to facilitate authentication mechanisms - HTTP/BASIC is configured by default - in your web application.
 
NOTE: Spring provides an integration component [ReactiveAuthenticationManagerAdapter](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/ReactiveAuthenticationManagerAdapter.html)
for leveraging your existing AuthenticationManager classes into the reactive application.

Below is a illustration of the dependencies created between Servlet Filters and Spring Reactive Authentication components:

WebFilter->AuthenticationWebFilter->ReactiveAuthenticationManager->ReactiveUserDetails->user_spec->request

## Serving your domain users
Spring Security's [HttpServerSecurityConfigurer](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html#securityMatcher-org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher) will wire in the a configured bean of type ReactiveAuthenticationManager, and if one is not available
will create a [UserDetailsRepositoryReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.3.RELEASE/api/org/springframework/security/authentication/UserDetailsRepositoryReactiveAuthenticationManager.html) 
That defers to [ReactiveUserDetailsService](https://docs.spring.io/spring-security/site/docs/5.1.0.M1/api/org/springframework/security/core/userdetails/ReactiveUserDetailsService.html)  
for user data lookup and credential storage.

Spring comes with ready-made implemenations for storing and looking up users in the MapReactiveUserDetailsService - simple for demos - but we want to go a little in depth. Lets implement our own ReactiveAuthenticationManager which responds with our custom UserDetails objects.  

First, the custom User domain object which implements UserDetails as prescribed by the UserDetailsService interface:

User.java:
    @Data
    @Slf4j
    public class User implements UserDetails {

        private final Account account;
        Collection<GrantedAuthority> authorities;

        public User(Account account, String roles) {
            this.authorities = Arrays.asList(roles.split(","))
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
            this.account = account;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.authorities;
        }

        @Override
        public String getPassword() {
            return account.getPassword();
        }
    
        @Override
        public String getUsername() {
            return account.getUsername();
        }

        @Override
        public boolean isAccountNonExpired() {
            return account.isActive();
        }

        @Override
        public boolean isAccountNonLocked() ...

        @Override
        public boolean isCredentialsNonExpired() {
            return account.isActive();
        }

        @Override
        public boolean isEnabled() {
            return account.isActive();
        }

        @Data
        public static class Account {

            private final String username;
            private final String password;
            private final boolean active;

            public Account(String username, String password, boolean active) {
                this.username = username;
                this.password = password;
                this.active = active;
            }
        }
    }

We can, otherwise back 


END.
