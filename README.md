# Sample Spring Security WebFlux

This article discuses the Spring Security configuration for apps that want to also use reactive [WebFlux](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html).

Spring Security [WebFlux](https://docs.spring.io/spring/docs/current/spring-framework-reference/web-reactive.html) is the framework that lets us declare request routing, and express security - like classical Spring Security - but using functional and reactive techniques.

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

Using the [AuthorizeExchangeSpec](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.AuthorizeExchangeSpec.html) by invoking `authorizeExchange()`, one can issue URI [PathPattern](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/util/matcher/PathPatternParserServerWebExchangeMatcher.html)'s that will match Access Control rules to paths on the service route.

For example, `hasRole()` method is a shorthand for `hasAuthority()` method where the user's [GrantedAuthority](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/core/GrantedAuthority.html) (aka privilege) is checked for specific values. The `hasRole()` requires each authority be prefixed with 'ROLE_'.

Finally, there is the `access()` method that takes a anonymous or otherwise custom implementation of [ReactiveAuthorizationManager](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authorization/ReactiveAuthorizationManager.html). This is usefule for in-hous authorization logic implementations.

Another useful component used when configuring SecurityWebFilterChain is the [CsrfSpec](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.CsrfSpec.html) enabled by calling `csrf()` method.  This lets us configure [CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet) tokens and handlers, or exclude CSRF entirely.

Lets see some sample configuration code.

SecurityConfiguration.java:

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
                .csrf().disable()
                .httpBasic()
                .and()
                .build();
        }

    }

Additionally the `and()` and `or()` and `disable()` methods lets us build another component's filter on the filter chain. In this case, we simply turn CSRF off, and configure HTTP Basic. Calling `build()` returns the completed [SecurityWebFilterChain](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/SecurityWebFilterChain.html).

## Authentication Providers & Managers

Heres where the real meat comes in: 

[ReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/ReactiveAuthenticationManager.html)
does the job of facilitating authentication mechanisms - e.g. HTTP/BASIC which is included automatically- in your web application.

NOTE: Spring provides an integration component [ReactiveAuthenticationManagerAdapter](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/ReactiveAuthenticationManagerAdapter.html)
for hoisting your existing, classic AuthenticationManager implementations into the reactive world.

### Custom Domain Users

The [UserDetailsRepositoryReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.3.RELEASE/api/org/springframework/security/authentication/UserDetailsRepositoryReactiveAuthenticationManager.html)
bean is provided automatically if there are no other configured ReactiveAuthenticationManagers `@Bean` definitions. This authentication manager defers principal/credential operations to a [ReactiveUserDetailsService](https://docs.spring.io/spring-security/site/docs/5.1.0.M1/api/org/springframework/security/core/userdetails/ReactiveUserDetailsService.html).

Spring comes with ready-made implemenations for storing and looking up users in the MapReactiveUserDetailsService - simple for demos - but we want to go a little in depth.  We'll complete this section by making 2 uses of this bean - one MapReactive, the other our own - to illustrate simplicity in overriding and levering this component.. 

First, the custom User domain object which implements UserDetails as prescribed by the UserDetailsService interface:

ExampleUser.java:

    @Data
    @Slf4j
    public class ExampleUser implements UserDetails {

        private final Account account;
        Collection<GrantedAuthority> authorities;

        public ExampleUser(Account account, String[] roles) {
            this.authorities = Arrays.asList(roles)
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
        public boolean isAccountNonLocked() {
            return account.isActive();
        }

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

            private String username;
            private String password;
            private boolean active;

            public Account(String username, String password, boolean active) {
                this.username = username;
                this.password = password;
                this.active = active;
            }

        }
    }

We need to provide a way to get our users out of a user service, in this demo we will use a pre-programmed List() of users to hold any UserDetails we want to expose through the app. We provide a few convenicne methods to setting up the object. Of significant import is the [PasswordEncoder](https://docs.spring.io/spring-security/site/docs/4.2.4.RELEASE/apidocs/org/springframework/security/crypto/password/PasswordEncoder.html) that is used to encrypt/encode (defaults to bcrypt) plaintext.

UserDetailServiceBean.java:

    @Configuration
    public class UserDetailServiceBeans {

        private static final PasswordEncoder pw = PasswordEncoderFactories.createDelegatingPasswordEncoder();

        private static UserDetails user(String u, String... roles) {
            return new ExampleUser(new ExampleUser.Account(u, pw.encode("password"), true),
                    roles);
        }

        private static final Collection<UserDetails> users = new    ArrayList<>(
            Arrays.asList(
                    user("thor", "ROLE_ADMIN"),
                    user("loki", "ROLE_USER"),
                    user("zeus", "ROLE_ADMIN", "ROLE_USER")
            ));
    //...

Now, with users available, we can wire in a UserDetailService. Lets start with the easy-to-use MapReactiveUserDetailService. We'll bind it to a spring profile "map-reactive" for use case demonstration.

UserDetailServiceBean.java:

    @Bean
    @Profile("map-reactive")
    public MapReactiveUserDetailsService mapReactiveUserDetailsService() {
        return new MapReactiveUserDetailsService(users);
    }

Because we have satisified all of the core componetns needed ot lock down our applicaiton, We can actually stop here with configuration.

On the other hand, what if I wanted to implement my own ReactiveUserDetailService? This can be accomplished! simply wire in an own implementation of ReactiveUserDetailsService as a bean. We'll bind it ot the spring profile "custom" for use case demonstration.

UserDetailServiceBeans.java:

    @Component
    @Profile("custom")
    class ExampleUserDetailService implements ReactiveUserDetailsService {

        @Override
        public Mono<UserDetails> findByUsername(String username) {
            Optional<UserDetails> maybeUser = users.stream().filter(u -> u.getUsername().equalsIgnoreCase(username)).findFirst();
            return maybeUser.map(Mono::just).orElse(Mono.empty());
        }
    }



END.
