package com.teamps.auth_service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ClaimsBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret.key}") // yml 에 설정한 jwt 키
    private String secretKey;

    @Value("${jwt.expiration}") // yml 에 설정한 토큰 만료시간 30분
    private long validityMilliseconds;

    // JWT 토큰 생성
    public String createToken(UserDetails userDetails) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityMilliseconds);
        Key key = Keys.hmacShaKeyFor(secretKey.getBytes());

        Claims claims = Jwts.claims()
                .subject(userDetails.getUsername())  // 사용자 이름
                .issuedAt(now)  // 발행 시간
                .expiration(validity)  // 만료 시간
                .build();  // Claims 객체로 빌드

        return Jwts.builder()
                .claims(claims)
                .signWith(key)
                .compact();
        }


}
