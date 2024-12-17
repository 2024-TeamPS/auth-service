package com.teamps.auth_service.dto.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.util.Map;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SocialProfileDto {

    private Map<String, Object> attributes;

    public long getProviderId(ClientRegistration provider) {
        String providerName = provider.getClientName();
        if (providerName.equalsIgnoreCase("google")) {
            return Long.parseLong(String.valueOf(attributes.get("id")));
        }

        return 0;
    }
}
