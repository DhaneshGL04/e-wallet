package com.github.Dhanesh.config; // Your current package

// Removed all security-related imports and Lombok's RequiredArgsConstructor
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.context.annotation.Bean;
import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
// Removed @EnableMethodSecurity as there's no method security to enable
public class SecurityConfig {

    // Removed all fields:
    // private final AuthEntryPointJwt authEntryPointJwt;
    // private final UserDetailsServiceImpl userDetailsService;
    // private static final String[] AUTH_WHITELIST;

    // Removed all @Bean methods:
    // authenticationJwtTokenFilter()
    // authenticationProvider()
    // userDetailsServiceDummy()
    // authenticationManager()
    // passwordEncoder()
    // corsConfigurationSource() - This will be inlined or handled differently if needed

    // The filterChain method is the only one left to configure HttpSecurity
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // Configure CORS to allow requests from your frontend
                .cors(cors -> cors
                        .configurationSource(request -> {
                            CorsConfiguration corsConfig = new CorsConfiguration();
                            // IMPORTANT: Make sure this matches your actual frontend URL
                            corsConfig.addAllowedOrigin("https://e-wallet-1-jdkv.onrender.com");
                            corsConfig.addAllowedMethod("*"); // Allow all HTTP methods
                            corsConfig.addAllowedHeader("*"); // Allow all headers
                            corsConfig.setAllowCredentials(true); // Allow credentials (e.g., cookies, auth headers)
                            corsConfig.setMaxAge(3600L); // Cache preflight for 1 hour
                            return corsConfig;
                        }))
                // Disable CSRF protection entirely
                .csrf().disable()
                // Authorize all requests without any authentication or authorization
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // Allow preflight requests
                        .anyRequest().permitAll() // Permit all other requests
                );

        // Removed all calls to add filters or authentication providers:
        // httpSecurity.authenticationProvider(authenticationProvider());
        // httpSecurity.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
