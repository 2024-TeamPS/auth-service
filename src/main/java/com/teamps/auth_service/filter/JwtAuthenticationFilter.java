package com.teamps.auth_service.filter;

import com.teamps.auth_service.util.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        // 클라이언트로부터 받은 HTTP 요청의 헤더에서 "Authorization" 값을 가져옴
        String authorizationHeader = request.getHeader("Authorization");

        // Authorization 헤더가 null 이 아니고 "Bearer "로 시작하는 경우에만 처리
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            // "Bearer " 이후의 문자열을 토큰으로 분리
            String token = authorizationHeader.substring(7);

            // 토큰이 유효한지 검사
            if (jwtTokenProvider.validateToken(token)) {
                // 토큰에서 인증 정보를 추출
                Authentication authentication = jwtTokenProvider.getAuthentication(token);

                // SecurityContext 에 인증 정보 설정 (Spring Security 에서 현재 사용자를 인증된 상태로 설정)
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        // 현재 필터 작업이 끝난 후 다음 필터로 요청을 전달
        filterChain.doFilter(request, response);
    }
}
