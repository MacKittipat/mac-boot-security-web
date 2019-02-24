package com.mackittipat.clientweb.config;

import com.mackittipat.clientweb.filter.MyAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final static Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private AuthenticationProvider myAuthenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("http://localhost:9000/login?redirectUrl=http://localhost:9001/")
                .and().addFilterAfter(new MyAuthenticationFilter(), BasicAuthenticationFilter.class);

//        http.authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("http://localhost:9000/login?redirectUrl=http://localhost:9001/")
//                .successHandler(this::loginSuccessHandler);
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(myAuthenticationProvider);
//    }

    private void loginSuccessHandler(HttpServletRequest request,
                  HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        boolean loginSuccess = Arrays.stream(request.getCookies())
                .anyMatch(c -> "loginSuccess".equals(c.getName()) && "true".equals(c.getValue()));
        log.info("Login result = {}", loginSuccess);
        if(loginSuccess) {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("", "", new ArrayList<>()));

        }
    }
}
