package com.teamps.auth_service.config;

import com.teamps.auth_service.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 기본 보안 설정 적용
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // 기본 로그인 페이지 대신, JWT 기반 인증으로만 보호
        http
            .csrf(AbstractHttpConfigurer::disable) // CSRF 보호를 비활성화 (API 서버에서는 필요 없음)
            .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated()); // 모든 요청에 인증을 요구

        // JwtAuthenticationFilter 필터를 등록하여 JWT 인증 처리
        http.addFilterBefore(jwtAuthenticationFilter, JwtAuthenticationFilter.class);

        return http.build();
    }

}
