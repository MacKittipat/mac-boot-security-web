package com.mackittipat.clientweb.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class MyAuthenticationProvider implements AuthenticationProvider {

    private final static Logger log = LoggerFactory.getLogger(MyAuthenticationProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();
        log.info("Principal={}, Credential={}", username, password);

        if("mac".equals(username) && "password".equals(password)) {
            return new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());
        }
        throw new BadCredentialsException("Invalid Credential (-_-!)");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
