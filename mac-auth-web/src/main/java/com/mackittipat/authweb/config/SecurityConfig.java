package com.mackittipat.authweb.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .successHandler(this::loginSuccessHandler);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication().withUser("admin").password(encoder.encode("password")).roles("ADMIN");
        auth.inMemoryAuthentication().withUser("mac").password(encoder.encode("password")).roles("USER");
    }

    private void loginSuccessHandler(HttpServletRequest httpServletRequest,
                                     HttpServletResponse httpServletResponse,
                                     Authentication authentication) throws IOException {
        Cookie cookie = new Cookie("authenticationSuccess", "true");
        httpServletResponse.addCookie(cookie);
        httpServletResponse.sendRedirect("/");
    }

//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//
////        UserDetails userDetails = User
////                .withUsername("mac")
////                .password(encoder.encode("password"))
////                .roles("USER")
////                .build();
////        return new InMemoryUserDetailsManager(userDetails);
//
//        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
//
//        userDetailsManager.createUser(
//                User.withUsername("mac")
//                        .password(encoder.encode("password"))
//                        .roles("USER").build());
//        userDetailsManager.createUser(
//                User.withUsername("admin")
//                        .password(encoder.encode("password"))
//                        .roles("ADMIN").build());
//
//        return userDetailsManager;
//    }
}
