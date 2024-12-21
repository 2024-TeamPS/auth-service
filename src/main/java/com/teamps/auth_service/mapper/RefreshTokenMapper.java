package com.teamps.auth_service.mapper;

import com.teamps.auth_service.domain.RefreshToken;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface RefreshTokenMapper {

    // 유저 ID로 리프레시 토큰 조회
    RefreshToken findByUserId(long userId);

    // 리프레시 토큰 생성
    void insertRefreshToken(RefreshToken refreshToken);

    // 유저 ID로 리프레시 토큰 삭제
    void deleteByUserId(long userId);

    // 해당 리프레시 토큰이 존재하는지 검색
    RefreshToken findByRefreshToken(String refreshToken);

    // 리프레시 토큰값을 이용하여 토큰 삭제
    void deleteByRefreshToken(String refreshToken);

}
