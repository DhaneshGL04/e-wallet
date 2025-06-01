package com.example.config; // Adjust package as per your project structure

import com.example.security.jwt.AuthEntryPointJwt; // Assuming this path
import com.example.security.jwt.AuthTokenFilter; // Assuming this path
import com.example.security.services.UserDetailsServiceImpl; // Assuming this path
import lombok.RequiredArgsConstructor;
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
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthEntryPointJwt authEntryPointJwt;
    private final UserDetailsServiceImpl userDetailsService;

    private static final String[] AUTH_WHITELIST = {
            "/api/v1/auth/**",
            "/v3/api-docs/**",
            "/v3/api-docs.yaml",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        // This bean is kept, but its effect on security enforcement is nullified by permitAll()
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        // This bean is kept and configured with its dependencies.
        // Its authentication logic will be bypassed by the filterChain's permitAll().
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        // This bean is kept.
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // This bean is kept.
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        // CORS configuration is retained as it's a common web requirement.
        httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // CSRF protection is disabled, as requested previously.
                .csrf().disable()
                // The following lines for exception handling and session management are commented out
                // as they are typically part of security enforcement.
                // .exceptionHandling().authenticationEntryPoint(authEntryPointJwt).and()
                // .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

                // CORE CHANGE: Authorize all requests without any authentication or authorization.
                // This line effectively disables all security enforcement for your project.
                .authorizeHttpRequests(auth -> auth
                        // Allow OPTIONS requests for preflight checks (common for CORS)
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // Permit all other requests
                        .anyRequest().permitAll()
                );

        // These filters and providers are still added to the chain,
        // but their security-enforcing actions are bypassed because `anyRequest().permitAll()`
        // has already granted access to all requests.
        httpSecurity.authenticationProvider(authenticationProvider());
        httpSecurity.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    // Define a CORS configuration source to allow requests from your frontend.
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // IMPORTANT: Make sure this matches your actual frontend URL
        configuration.setAllowedOrigins(Collections.singletonList("https://e-wallet-1-jdkv.onrender.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With", "Accept"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // Cache preflight for 1 hour

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Apply this CORS config to all paths
        return source;
    }
}
