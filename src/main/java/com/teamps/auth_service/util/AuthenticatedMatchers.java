package com.teamps.auth_service.util;

public class AuthenticatedMatchers {

    private AuthenticatedMatchers() {}

    public static final String[] matcherArray = {
            // v3 설정 추가할 필요 있을 수 있음
            "/",
            "/auth/code/**",
            "/auth/login/**",
            "/auth/logout",
            "/auth/reissue",
            "/api-docs",
            "/api-docs/**",
            "/v3/**",
            "/v3/api-docs/**",
            "/swagger-ui/index.html",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };
}
