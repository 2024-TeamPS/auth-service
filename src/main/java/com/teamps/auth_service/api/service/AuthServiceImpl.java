package com.teamps.auth_service.api.service;

import com.teamps.auth_service.dto.dto.OAuthTokenDto;
import com.teamps.auth_service.dto.dto.SocialProfileDto;
import com.teamps.auth_service.dto.response.TokenResponse;
import com.teamps.auth_service.mapper.BlackListMapper;
import com.teamps.auth_service.mapper.RefreshTokenMapper;
import com.teamps.auth_service.model.BlackList;
import com.teamps.auth_service.model.RefreshToken;
import com.teamps.auth_service.util.JwtTokenProvider;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String BEARER_TYPE = "Bearer";
    private final InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenMapper refreshTokenMapper;
    private final BlackListMapper blackListMapper;

    public URI getCode(String providerName) {
        try {
            ClientRegistration provider = inMemoryClientRegistrationRepository.findByRegistrationId(providerName);

            String uri = provider.getProviderDetails().getAuthorizationUri()
                    + "response_type=code&redirect_uri="
                    + provider.getRedirectUri()
                    + "&client_id="
                    + provider.getClientId()
                    + "&scope=openid";

            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new RuntimeException("URI 생성 오류", e);
        }
    }

    public TokenResponse login(String providerName, String code) {
        ClientRegistration provider = inMemoryClientRegistrationRepository.findByRegistrationId(providerName);

        OAuthTokenDto token = getToken(code, provider);

        long userId = getUserProfile(token, provider);

        RefreshToken refreshToken = refreshTokenMapper.findByUserId(userId);

        if (refreshToken != null) {
            String refreshTokenValue = refreshToken.getRefreshToken();

            BlackList blackList = BlackList.builder()
                    .token(refreshTokenValue)
                    .expiration(jwtTokenProvider.getExpiration(refreshTokenValue))
                    .build();

            blackListMapper.insertBlackList(blackList);
            refreshTokenMapper.deleteByRefreshToken(refreshTokenValue);
        }

        return createToken(userId);
    }

    private TokenResponse createToken(long userId) {
        String accessToken = jwtTokenProvider.createAccessToken(String.valueOf(userId));
        String refreshToken = jwtTokenProvider.createRefreshToken();

        RefreshToken token = RefreshToken.builder()
                .userId(userId)
                .refreshToken(refreshToken)
                .build();

        refreshTokenMapper.insertRefreshToken(token);

        return TokenResponse.builder()
                .tokenType(BEARER_TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private OAuthTokenDto getToken(String code, ClientRegistration provider) {
        return WebClient.create()
                .post()
                .uri(provider.getProviderDetails().getTokenUri())
                .headers(header -> {
                    header.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                    header.setAcceptCharset(Collections.singletonList(StandardCharsets.UTF_8));
                })
                .bodyValue(tokenRequest(code, provider))
                .retrieve()
                .bodyToMono(OAuthTokenDto.class)
                .block();
    }

    private MultiValueMap<String, String> tokenRequest(String code, ClientRegistration provider) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("code", code);
        formData.add("grant_type", "authorization_code");
        formData.add("redirect_uri", provider.getRedirectUri());
        formData.add("client_secret", provider.getClientSecret());
        formData.add("client_id", provider.getClientId());
        return formData;
    }

    private long getUserProfile(OAuthTokenDto token, ClientRegistration provider) {
        Map<String, Object> userAttributes = getUserAttributes(provider, token);
        SocialProfileDto profile = new SocialProfileDto(userAttributes);

        return profile.getProviderId(provider);
    }

    private Map<String, Object> getUserAttributes(ClientRegistration provider, OAuthTokenDto token) {
        return WebClient.create()
                .get()
                .uri(provider.getProviderDetails().getUserInfoEndpoint().getUri())
                .headers(header -> header.setBearerAuth(token.getAccess_token()))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();
    }

    public TokenResponse reissue(String refreshToken) {
        RefreshToken token = refreshTokenMapper.findByRefreshToken(refreshToken);
        if (token == null) {
            return null;
        }

        if (!jwtTokenProvider.validateToken(token.getRefreshToken())) {
            return null;
        }

        long userId = token.getUserId();

        refreshTokenMapper.deleteByRefreshToken(refreshToken);

        BlackList blackList = BlackList.builder()
                .token(refreshToken)
                .expiration(jwtTokenProvider.getExpiration(refreshToken))
                .build();

        blackListMapper.insertBlackList(blackList);

        return createToken(userId);
    }

    public void logout(String accessToken, String refreshToken) {
        refreshTokenMapper.deleteByRefreshToken(refreshToken);

        if (jwtTokenProvider.validateToken(accessToken)) {
            BlackList access = BlackList.builder()
                    .token(accessToken)
                    .expiration(jwtTokenProvider.getExpiration(accessToken))
                    .build();

            blackListMapper.insertBlackList(access);
        }

        if (jwtTokenProvider.validateToken(refreshToken)) {
            BlackList refresh = BlackList.builder()
                    .token(refreshToken)
                    .expiration(jwtTokenProvider.getExpiration(refreshToken))
                    .build();

            blackListMapper.insertBlackList(refresh);
        }
    }

}
