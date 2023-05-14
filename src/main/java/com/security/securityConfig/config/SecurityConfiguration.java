package com.security.securityConfig.config;

import com.security.securityConfig.user.Role;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.security.securityConfig.user.Permission.ADMIN_CREATE;
import static com.security.securityConfig.user.Permission.ADMIN_DELETE;
import static com.security.securityConfig.user.Permission.ADMIN_READ;
import static com.security.securityConfig.user.Permission.ADMIN_UPDATE;
import static com.security.securityConfig.user.Permission.MANAGER_CREATE;
import static com.security.securityConfig.user.Permission.MANAGER_DELETE;
import static com.security.securityConfig.user.Permission.MANAGER_READ;
import static com.security.securityConfig.user.Permission.MANAGER_UPDATE;
import static com.security.securityConfig.user.Role.ADMIN;
import static com.security.securityConfig.user.Role.MANAGER;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("ENTRE EN FILTER CHAIN");
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .antMatchers(
                        "/api/v1/auth/**",
                        "/v2/api-docs",
                        "/v3/api-docs",
                        "/v3/api-docs/**",
                        "/swagger-resources",
                        "/swagger-resources/**",
                        "/configuration/ui",
                        "/configuration/security",
                        "/swagger-ui/**",
                        "/webjars/**",
                        "/swagger-ui.html"
                )
                .permitAll()


                .antMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())


                .antMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                .antMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                .antMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                .antMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())


                .antMatchers("/api/v1/admin/**").hasRole(ADMIN.name())

                 .antMatchers(GET, "/api/v1/admin/**").hasAuthority(ADMIN_READ.name())
                 .antMatchers(POST, "/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
                 .antMatchers(PUT, "/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
                 .antMatchers(DELETE, "/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())


                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
        ;

        return http.build();
    }
}

