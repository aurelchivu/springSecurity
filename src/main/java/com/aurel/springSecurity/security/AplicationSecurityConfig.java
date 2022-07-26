package com.aurel.springSecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.aurel.springSecurity.security.ApplicationUserRole.*;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class AplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {

        UserDetails carlaUser = User.builder()
                .username("carla")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name())
                .build();

        UserDetails aurelChivuUser = User.builder()
                .username("aurelchivu")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name())
                .build();

        return new InMemoryUserDetailsManager(carlaUser, aurelChivuUser);
    }
}