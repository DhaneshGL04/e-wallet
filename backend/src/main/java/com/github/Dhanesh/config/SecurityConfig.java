package com.github.Dhanesh.config;

import com.github.Dhanesh.security.AuthEntryPointJwt;
import com.github.Dhanesh.security.AuthTokenFilter;
import com.github.Dhanesh.security.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource; // Keep this import if you prefer a separate CorsConfigurationSource bean
import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Re-enable if you plan to use method-level security (e.g., @PreAuthorize)
public class SecurityConfig {

    private final AuthEntryPointJwt authEntryPointJwt;
    private final UserDetailsServiceImpl userDetailsService;

    // Inject AuthEntryPointJwt and UserDetailsServiceImpl
    public SecurityConfig(AuthEntryPointJwt authEntryPointJwt, UserDetailsServiceImpl userDetailsService) {
        this.authEntryPointJwt = authEntryPointJwt;
        this.userDetailsService = userDetailsService;
    }

    // Define the JWT authentication filter as a bean
    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    // Configure the AuthenticationProvider
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    // Expose AuthenticationManager as a bean
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // Define the password encoder bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // Configure CORS to allow requests from your frontend
                .cors(cors -> cors
                        .configurationSource(request -> {
                            CorsConfiguration corsConfig = new CorsConfiguration();
                            corsConfig.addAllowedOrigin("https://e-wallet-1-jdkv.onrender.com");
                            corsConfig.addAllowedMethod("*"); // Allow all HTTP methods
                            corsConfig.addAllowedHeader("*"); // Allow all headers
                            corsConfig.setAllowCredentials(true); // Allow credentials (e.g., cookies, auth headers)
                            corsConfig.setMaxAge(3600L); // Cache preflight for 1 hour
                            return corsConfig;
                        }))
                // Disable CSRF protection for API calls (common with JWT)
                .csrf(csrf -> csrf.disable())
                // Configure exception handling for unauthorized access
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPointJwt))
                // Set session management to stateless (no session will be created or used)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Authorize requests
                .authorizeHttpRequests(auth -> auth
                        // Allow specific public endpoints without authentication
                        .requestMatchers("/api/auth/**", "/h2-console/**", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Allow preflight requests for all paths
                        // All other requests require authentication
                        .anyRequest().authenticated()
                );

        // Add the custom JWT authentication filter before the Spring Security's default UsernamePasswordAuthenticationFilter
        httpSecurity.authenticationProvider(authenticationProvider());
        httpSecurity.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
