package com.teamps.auth_service.mapper;

import com.teamps.auth_service.model.BlackList;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface BlackListMapper {

    // 블랙리스트 생성
    int insertBlackList(BlackList blackList);

    // 해당 토큰이 있는지 탐색
    BlackList findByToken(String token);

}
