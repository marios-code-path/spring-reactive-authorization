# Sample Spring Security WebFlux

This article discuses the Spring Security configuration for apps that want to also use
reactive WebFlux.

Spring Security WebFlux is the framework that lets us declare request routing, and express security - like classical Spring Security - but using functional and reactive techniques.

## Getting Started

To get started, we can call 'start.spring.io' to generate a baseline app with the following dependencies:

 * [WebFlux](https://docs.spring.io/spring/docs/5.0.0.BUILD-SNAPSHOT/spring-framework-reference/html/web-reactive.html) 
 * [Reactive Security 5](https://spring.io/blog/2017/10/04/spring-tips-reactive-spring-security)
 * [lombok](https://projectlombok.org)

Next, lets briefly, and lightly take a look at how this framework puts things together. We can compose our sample app throughout this article while highlighting common and oft-used architectural pieces.

## Reactive Authorization Components
How does Spring Security let us describe our security details? 

The [ServerHttpSecurity](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html) 
is the reactive version for [HttpSecurity](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/config/annotation/web/builders/HttpSecurity.html) which allows us to program web-based security 
rules for specific web endpoints. We are given a variety of specifications that let us decide on which part of the [ServerWebExchange](https://docs.spring.io/spring/docs/current/javadoc-api/org/springframework/web/server/ServerWebExchange.html) we can lock down. To do this, ServerHttpSecurity gives us a few friendly components. For example, using the [AuthorizeExchangeSpec](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.AuthorizeExchangeSpec.html), one can lock down service URI's with Role Based Access Control, custom authorization, or disable authorization altogether. This component lets us harness the [PathPattern](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/util/matcher/PathPatternParserServerWebExchangeMatcher.html) matcher through a method '.pathMatchers(...)'. The 'hasRole(...)' method actually configures an [ReactiveAuthorizationManager](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authorization/ReactiveAuthorizationManager.html) to check the user's [GrantedAuthority](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/core/GrantedAuthority.html) assignments. This is a shortcut to 'hasAuthority(...)' method, but requires each authority (aka privilege) be prefixed with 'ROLE_'.
Lets continue with with [ReactiveAuthorizationManager](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authorization/ReactiveAuthorizationManager.html) which lets us express how authorization decisions are made. In most cases, we have just the role needed to access a resource. We express authorization this way using [hasRole](https://hasRole) or [hasAuthority](https://hasAuthority) methods. A third method 'access()' lets us administer customized logic to an endpoint by implementing our own ReactiveAuthorizationManager with custom handling.

Another common component used when configuring SecurityWebFilterChain via ServerHttpSecurity is the [CsrfSpec](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.CsrfSpec.html) enabled by calling .csrf() method.  This lets us configure [CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet) tokens and handlers, or exclude CSRF entirely.

Configured security rules on our service paths (matched exchanges) are ultimately used to program the operations performed within the [SecurityWebFilterChain](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/SecurityWebFilterChain.html) instance of [WebFilterChain](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/server/WebFilterChain.html). See [WebFilter](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/server/WebFilter.html) for more information on this process. 

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
                .csrf().disable()
                .httpBasic()
                .and()
                .build();
        }

    }

Using and() methods lets us chain additional rules to our security configuration. In this case, we simply turn CSRF off, then proceed to tell Spring Security that we will be using HTTP Basic security. Calling the build() method is the last thing we to complete the [SecurityWebFilterChain](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/SecurityWebFilterChain.html).

## Reactive Authentication Components
By default, a [HttpServerSecurityConfigurer](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html#securityMatcher-org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher) creates a base-line instance for [ServerHttpSecurity](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html). It will configure an instance of
[ReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/ReactiveAuthenticationManager.html)
which is the reactive component for traditional [AuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/AuthenticationManager.html).
The job of the AuthenticationManager is to facilitate various authentication mechanisms - e.g. HTTP/BASIC is included automatically- in your web application.
 
NOTE: Spring provides an integration component [ReactiveAuthenticationManagerAdapter](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/ReactiveAuthenticationManagerAdapter.html)
for hoisting your existing, classic AuthenticationManager implementations into the reactive world.

### Authenticion and Domain Users
The baseline ReactiveAuthenticationManager that gets created by our HttpServerSecurityConfigurer bean is the[UserDetailsRepositoryReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.3.RELEASE/api/org/springframework/security/authentication/UserDetailsRepositoryReactiveAuthenticationManager.html).
This bean defers principal/credential operations to a [ReactiveUserDetailsService](https://docs.spring.io/spring-security/site/docs/5.1.0.M1/api/org/springframework/security/core/userdetails/ReactiveUserDetailsService.html)  
for user data lookup and credential management.

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
