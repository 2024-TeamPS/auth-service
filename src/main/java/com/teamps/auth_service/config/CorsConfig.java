package com.teamps.auth_service.config;

import org.springframework.web.filter.CorsFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        // UrlBasedCorsConfigurationSource 객체를 생성하여 특정 URL 패턴에 대해 CORS 설정을 지정할 수 있게 함
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // 새로운 CORS 설정 객체 생성
        CorsConfiguration config = new CorsConfiguration();

        // 쿠키와 같은 자격 증명을 클라이언트에서 포함할 수 있도록 허용 (CORS 요청에서 인증 정보 허용)
        config.setAllowCredentials(true);

        // 모든 도메인에서의 요청을 허용 (와일드카드 패턴 사용)
        config.addAllowedOriginPattern("*");

        // 특정 도메인(http://localhost:3000)에서의 요청을 허용 (개발 환경에서 사용)
        config.addAllowedOrigin("http://localhost:3000");

        // 실제 서비스 도메인에 대한 요청을 허용 (서비스 배포 시 도메인을 이 부분에 설정해야 함)
        config.addAllowedOrigin("http://서비스도메인");

        // 모든 헤더를 허용 (클라이언트가 어떤 헤더를 보내도 서버에서 허용)
        config.addAllowedHeader("*");

        // 모든 응답 헤더를 클라이언트에 노출 (클라이언트가 모든 응답 헤더를 볼 수 있음)
        config.addExposedHeader("*");

        // 모든 HTTP 메서드(GET, POST, PUT, DELETE 등)를 허용
        config.addAllowedMethod("*");

        // 지정한 URL 패턴에 대해 위에서 설정한 CORS 정책을 적용 (여기서는 모든 URL에 대해 적용)
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }
}
