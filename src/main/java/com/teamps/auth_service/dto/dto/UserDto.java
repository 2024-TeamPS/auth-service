package com.teamps.auth_service.dto.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
public class UserDto {

    private Long userId;
    private String nickname;
    private String socialType;
    private LocalDateTime joinTime;
    private Boolean isDeleted;
    private LocalDateTime deleteTime;
}
