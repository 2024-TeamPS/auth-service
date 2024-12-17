package com.teamps.auth_service.api.service;


import com.teamps.auth_service.dto.response.TokenResponse;

import java.net.URI;

public interface AuthService {
    URI getCode(String providerName);

    TokenResponse login(String providerName, String code);

    TokenResponse reissue(String refreshToken);

    void logout(String accessToken, String refreshToken);


}
