package com.mackittipat.clientweb.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

public class MyAuthenticationFilter extends OncePerRequestFilter {

    private final static Logger log = LoggerFactory.getLogger(MyAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("Filtering at {}", request.getRequestURL());
        boolean loginSuccess = Arrays.stream(request.getCookies())
                .anyMatch(c -> "loginSuccess".equals(c.getName()) && "true".equals(c.getValue()));

        log.info("Login success = {}", loginSuccess);
        if(loginSuccess) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("", "", new ArrayList<>()));
        }

        filterChain.doFilter(request, response);
    }
}
