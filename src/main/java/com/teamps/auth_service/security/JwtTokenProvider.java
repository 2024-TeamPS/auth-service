package com.teamps.auth_service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
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
    private long validityInMilliseconds;

    // JWT 토큰 생성
    public String createToken(UserDetails userDetails) {
        Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }


    // JWT 토큰에서 사용자 이름 추출
    public String getUsernameFromToken(String token) {
        return parseClaims(token).getSubject(); // subject 로 사용자 이름 추출
    }


    // JWT 토큰 검증
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


    // JWT 토큰 만료 여부 체크
    private boolean isTokenExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }


    // 토큰에서 Claims 추출
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


}
