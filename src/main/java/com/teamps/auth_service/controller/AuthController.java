package com.teamps.auth_service.controller;

import com.teamps.auth_service.service.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final JwtTokenService jwtTokenService;

    @Value("${jwt.expiration}")
    private long expirationTime;

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String bearerToken) {
        String token = bearerToken.substring(7); // Bearer 제외한 토큰만 추출
        jwtTokenService.blacklistToken(token, expirationTime); // 블랙리스트에 등록

        return ResponseEntity.ok("로그아웃 성공");
    }
}
