package com.teamps.auth_service.config;

import com.teamps.auth_service.util.AuthenticatedMatchers;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // REST API 에서는 기본적으로 HTML 폼 로그인이 필요 없으므로 비활성화
                .formLogin(AbstractHttpConfigurer::disable)

                // HTTP Basic 인증 방식을 사용하지 않음 (JWT 와 같은 토큰 기반 인증 방식을 사용할 예정이므로 비활성화)
                .httpBasic(HttpBasicConfigurer::disable)

                // CSRF(Cross-Site Request Forgery) 보호 비활성화 (REST API 에서는 보통 Stateless 방식이므로 CSRF 비활성화)
                .csrf(CsrfConfigurer::disable)

                // 세션 관리를 비활성화하고, REST API 에서 상태를 유지하지 않도록 Stateless 정책 사용
                .sessionManagement(configurer -> configurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 요청에 대한 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        // AuthenticatedMatchers.matcherArray 에 포함된 경로들은 인증 없이 접근 가능하도록 허용
                        .requestMatchers(AuthenticatedMatchers.matcherArray)
                        .permitAll()
                        // 나머지 모든 요청은 인증이 필요함
                        .anyRequest()
                        .authenticated())

                // CORS(Cross-Origin Resource Sharing) 필터 추가
                // 외부 도메인에서 서버로의 요청을 허용하기 위해 CORS 설정 적용
                .addFilter(corsConfig.corsFilter())

                // OAuth2 로그인을 기본 설정으로 활성화
                .oauth2Login(Customizer.withDefaults());
        return http.build();
    }

}
