package com.teamps.auth_service.util;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

// 인증되지 않은 사용자의 요청을 처리하는 클래스
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {
        // 현재 응답 상태 코드 확인
        int status = response.getStatus();

        // 응답 상태 코드가 200(정상)인 경우, 인증 실패로 401 상태 코드(통신 권한 없음) 설정
        if (status == 200) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
