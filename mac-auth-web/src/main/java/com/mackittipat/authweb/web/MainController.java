package com.mackittipat.authweb.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

    private final static Logger log = LoggerFactory.getLogger(MainController.class);

    @GetMapping("/")
    public String home(Model model, Authentication authentication) {

        User user = (User) authentication.getPrincipal();
        String authority = user.getAuthorities().stream()
                .findFirst()
                .orElseGet(() -> new SimpleGrantedAuthority("USER")).getAuthority();

        log.info("Principal = {}", user.getUsername());
        log.info("Credential = {}", user.getPassword());
        log.info("Authority = {}", authority);
        log.info("Detail = {}", authentication.getDetails());

        model.addAttribute("user", user);
        model.addAttribute("authority", authority);

        return "home";
    }
}
