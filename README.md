# Sample Spring Security WebFlux

This article discuses the Spring Security configuration for apps that want to also use
reactive WebFlux.

Spring Security WebFlux is the framework that lets us declare request routing, and express security - like classical Spring Security - but using functional and reactive techniques.

## Getting Started

To get started, we can call 'start.spring.io' to generate a baseline app with the following dependencies:

 * [WebFlux](https://docs.spring.io/spring/docs/5.0.0.BUILD-SNAPSHOT/spring-framework-reference/html/web-reactive.html) 
 * [Reactive Security 5](https://spring.io/blog/2017/10/04/spring-tips-reactive-spring-security)
 * [lombok](https://projectlombok.org)
 
You can additionally download the baseline project from [start.spring.io](http://start.spring.io/starter.zip?type=maven-project&language=java&bootVersion=2.0.3.RELEASE&baseDir=security&groupId=com.example&artifactId=security&name=security&description=Demo+Reactive+Security+Project&packageName=com.example.security&packaging=jar&javaVersion=1.8&autocomplete=&generate-project=&style=security&style=lombok&style=webflux)

Next, lets briefly, and lightly take a look at how this framework puts things together. We can compose our sample app throughout this article while highlighting common and oft-used architectural pieces.

## Reactive Authorization Components

The [ServerHttpSecurity](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html) 
is the reactive version for [HttpSecurity](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/config/annotation/web/builders/HttpSecurity.html) which allows us to program web-based security 
rules for specific web endpoints. This API harnesses [ServerWebExchangeMatcher](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/util/matcher/ServerWebExchangeMatcher.html)'s
to setup security rules on our service paths. They are used to configure the [WebFilter](http://WebFilter) security . There are many ServeWebExchangeMatchers, aligned with the DSL that engages the nature of it's configured component. For example, 


By default, a [HttpServerSecurityConfigurer](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html#securityMatcher-org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher) 

In particular, a [ReactiveAuthorizationManager](https://) lets us express how authorization decisions are made. In most cases, we have just the role needed to access a resource. We express authorization this way using [hasRole](https://hasRole) or [hasAuthority](https://hasAuthority) methods. A third method lets us administer a customized [ReactiveAuthorizationManager] to an endpoint as seen in the sample code below:

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
                .hasAuthority("ROLE_USER")
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

## Reactive Authentication Components
By default, the [ServerHttpSecurity] instance will configure an instance of
[ReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/ReactiveAuthenticationManager.html)
which is the reactive component for traditional [AuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/AuthenticationManager.html)
whose job it is to facilitate various authentication mechanisms - e.g. HTTP/BASIC is included automatically- in your web application.
 
NOTE: Spring provides an integration component [ReactiveAuthenticationManagerAdapter](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/ReactiveAuthenticationManagerAdapter.html)
for leveraging your existing AuthenticationManager classes into the reactive application.


## Domain Users
 will wire in the a configured bean of type ReactiveAuthenticationManager, and if one is not available
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
