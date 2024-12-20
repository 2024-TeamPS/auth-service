package com.teamps.auth_service.config;

import com.teamps.auth_service.filter.JwtAuthenticationFilter;
import com.teamps.auth_service.util.AuthenticatedMatchers;
import com.teamps.auth_service.util.JwtAccessDeniedHandler;
import com.teamps.auth_service.util.JwtAuthenticationEntryPoint;
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
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
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

                // 이 설정을 통해 요청이 기본 인증 필터로 처리되기 전에 JWT 토큰 검증을 수행
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                // 예외 상황 처리 설정
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        // 인증된 사용자가 필요한 리소스에 접근할 수 없을 때 처리하는 핸들러
                        .accessDeniedHandler(new JwtAccessDeniedHandler())
                        // 인증되지 않은 사용자가 요청 시 발생하는 예외 처리
                        .authenticationEntryPoint(new JwtAuthenticationEntryPoint()))
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        //BCrypt Encoder 사용
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
