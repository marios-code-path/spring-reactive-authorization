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

## Reactive Components Configuration  

The [ServerHttpSecurity](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/web/server/ServerHttpSecurity.html) 
is the reactive version for [HttpSecurity](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/config/annotation/web/builders/HttpSecurity.html) which allows us to program web-based security 
rules for specific requests. This API harnesses [ServerWebExchangeMatcher](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/server/util/matcher/ServerWebExchangeMatcher.html)
to define security rules against our definitions.

== Possible example picture depicting this demo

## Security WebFilter
By default, the reactive ServerHttpSecurity instance will invoke an
[ReactiveAuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/ReactiveAuthenticationManager.html)
which is the reactive component for traditional [AuthenticationManager](https://docs.spring.io/spring-security/site/docs/5.0.x/api/org/springframework/security/authentication/AuthenticationManager.html) 
This bean, whose job it is to facilitate authentication mechanism (oauth2 exchange, HTTP/basic, etc) between your 
user base, and the web application.
 
But as we will see, Spring provides all the machinery for getting access to as user database, by leveraging 
[ReactiveAuthenticationManagerAdapter](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/ReactiveAuthenticationManagerAdapter.html) 
to provide access to all our reactive credential components (JDBC, LDAP, etc)

ReactiveUserDetailsAuthenticationManager bean which does the chore of exposing details (e.g. current user) to the request context.
WebFilter->AuthenticationWebFilter->ReactiveAuthenticationManager->ReactiveUserDetails->user_spec->request

## Putting it together

Lets define how to do this:


END.
