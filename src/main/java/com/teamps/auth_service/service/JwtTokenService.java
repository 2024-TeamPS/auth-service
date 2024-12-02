package com.teamps.auth_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String BLACKLIST_PREFIX = "blacklist:";

    // JWT 토큰 블랙리스트 처리
    public void blacklistToken(String token, long expirationTime) {
        redisTemplate.opsForValue().set(BLACKLIST_PREFIX + token, "true", expirationTime, TimeUnit.SECONDS);
    }

    // 블랙리스트에 있는지 체크
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + token));
    }
}
