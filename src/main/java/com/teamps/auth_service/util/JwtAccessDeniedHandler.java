package com.teamps.auth_service.util;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

// 인증된 사용자가 접근 권한이 없는 리소스를 요청할 경우 처리하는 클래스
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 응답 상태 코드를 403 (Forbidden, 요청 리소스에 대한 권한 없음)으로 설정
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
}
