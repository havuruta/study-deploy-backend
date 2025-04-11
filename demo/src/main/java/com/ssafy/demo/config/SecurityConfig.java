package com.ssafy.demo.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import com.ssafy.demo.security.jwt.JwtAccessDeniedHandler;
import com.ssafy.demo.security.jwt.JwtAuthenticationEntryPoint;
import com.ssafy.demo.security.jwt.JwtAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    // Handler 추가
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }




    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF 설정 Disable
        http.csrf(
                csrfCustomizer -> csrfCustomizer
                        .ignoringRequestMatchers(antMatcher("/h2-console/**"))
                        .disable()
        );
        // 헤더 설정
        http.headers(
                // h2-console에서 iframe을 사용함. X-Frame-Options을 위해 sameOrigin 설정
                headersCustomizer -> headersCustomizer
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
        );
        // 인증 설정
        http.authorizeHttpRequests(
                authorizeCustomizer -> authorizeCustomizer
                        .requestMatchers(antMatcher("/h2-console/**")).permitAll()
                        .requestMatchers(antMatcher("/auth/**")).permitAll()
                        .requestMatchers(antMatcher("/swagger-ui/**")).permitAll()
                        .requestMatchers(antMatcher("/v3/api-docs/**")).permitAll()
                        .anyRequest().permitAll()
        );
//---------------------------------------------
        http.exceptionHandling(
                exceptionHandler -> exceptionHandler.accessDeniedHandler(
					jwtAccessDeniedHandler::handle
                )
        );

        http.exceptionHandling(
                exceptionHandler -> exceptionHandler.authenticationEntryPoint(
					jwtAuthenticationEntryPoint::commence
                )
        );
//---------------------------------------------

        http.sessionManagement(
                sessionCustomizer -> sessionCustomizer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);



        return http.build();
    }
}
