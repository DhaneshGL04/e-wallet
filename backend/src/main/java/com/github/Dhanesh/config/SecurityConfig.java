package com.github.Dhanesh.config; // Your current package

// Removed imports for non-existent security classes:
// import com.github.Dhanesh.security.jwt.AuthEntryPointJwt;
// import com.github.Dhanesh.security.jwt.AuthTokenFilter;
// import com.github.Dhanesh.security.services.UserDetailsServiceImpl;

// Keep these standard Spring and Lombok imports
import lombok.RequiredArgsConstructor; // Still useful if you add other final fields later
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User; // Required for dummy UserDetailsService
import org.springframework.security.core.userdetails.UserDetails; // Required for dummy UserDetailsService
import org.springframework.security.core.userdetails.UserDetailsService; // Required for dummy UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException; // Required for dummy UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder; // New: Using NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter; // New: For dummy AuthTokenFilter

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
// Removed @RequiredArgsConstructor here because we are removing the final fields
// which were causing the "cannot find symbol" errors in the constructor injection.
public class SecurityConfig {

    // Removed the fields that refer to the missing classes:
    // private final AuthEntryPointJwt authEntryPointJwt;
    // private final UserDetailsServiceImpl userDetailsService;

    private static final String[] AUTH_WHITELIST = {
            "/api/v1/auth/**",
            "/v3/api-docs/**",
            "/v3/api-docs.yaml",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };

    @Bean
    public OncePerRequestFilter authenticationJwtTokenFilter() {
        // Since AuthTokenFilter is not found, we return a generic OncePerRequestFilter
        // that does nothing but pass the request along.
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                // With security disabled by `anyRequest().permitAll()`, this filter is effectively a no-op.
                filterChain.doFilter(request, response);
            }
        };
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // Since UserDetailsServiceImpl is not found, we provide a simple dummy
        // UserDetailsService that will not find any users.
        // This allows the bean to be created without compilation errors.
        authProvider.setUserDetailsService(userDetailsServiceDummy());
        authProvider.setPasswordEncoder(passwordEncoder()); // Using NoOpPasswordEncoder
        return authProvider;
    }

    @Bean
    public UserDetailsService userDetailsServiceDummy() {
        // A placeholder UserDetailsService. Since `anyRequest().permitAll()` is used,
        // actual user loading for authentication won't be performed.
        return username -> {
            throw new UsernameNotFoundException("User not found (security disabled)");
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        // This bean is kept as it is.
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // For a hobby project with no security, NoOpPasswordEncoder is simplest.
        // It means no password hashing or verification is performed.
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf().disable();
                // Removed the commented-out exceptionHandling and sessionManagement
                // as they are typically tied to security enforcement.

                // THIS IS THE CRUCIAL PART TO DISABLE ALL SECURITY:
                // All requests are permitted without authentication or authorization.
                httpSecurity.authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Allow preflight requests
                        .anyRequest().permitAll() // Permit all other requests
                );

        // These beans are still wired into the chain, but their security logic
        // is bypassed because `anyRequest().permitAll()` already grants access.
        httpSecurity.authenticationProvider(authenticationProvider());
        httpSecurity.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Collections.singletonList("https://e-wallet-1-jdkv.onrender.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "Accept"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
