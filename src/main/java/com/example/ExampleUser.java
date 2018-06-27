package com.example;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

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