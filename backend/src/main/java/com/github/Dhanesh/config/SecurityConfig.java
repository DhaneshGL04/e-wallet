package com.github.Dhanesh.config;

import com.github.Dhanesh.security.jwt.AuthEntryPointJwt;
import com.github.Dhanesh.security.jwt.AuthTokenFilter;
import com.github.Dhanesh.security.services.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod; // Keep this import, though its usage will change

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthEntryPointJwt authEntryPointJwt;
    private final UserDetailsServiceImpl userDetailsService;

    // AUTH_WHITELIST is no longer strictly necessary as all requests will be permitted
    private static final String[] AUTH_WHITELIST = {
            "/api/v1/auth/**",
            "/v3/api-docs/**",
            "/v3/api-docs.yaml",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        // Disabling all security for development/hobby project purposes.
        // This configuration allows all requests without authentication or authorization.
        httpSecurity
                .cors(cors -> cors
                        .configurationSource(request -> {
                            org.springframework.web.cors.CorsConfiguration corsConfig = new org.springframework.web.cors.CorsConfiguration();
                            corsConfig.addAllowedOrigin("https://e-wallet-1-jdkv.onrender.com");
                            corsConfig.addAllowedMethod("*"); // Allow all methods for CORS
                            corsConfig.addAllowedHeader("*"); // Allow all headers for CORS
                            corsConfig.setAllowCredentials(true);
                            corsConfig.setMaxAge(3600L); // Cache preflight for 1 hour
                            return corsConfig;
                        }))
                .csrf().disable() // Disable CSRF protection
                .exceptionHandling().authenticationEntryPoint(authEntryPointJwt).and() // Keep this for now, but it won't be triggered if all requests are permitted
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and() // Keep stateless session
                .authorizeHttpRequests()
                .anyRequest().permitAll(); // Permit all requests

        // The following lines related to authentication providers and filters are now effectively bypassed
        // because .anyRequest().permitAll() takes precedence.
        // However, keeping them here won't cause issues if you decide to re-enable security later.
        httpSecurity.authenticationProvider(authenticationProvider());
        httpSecurity.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
