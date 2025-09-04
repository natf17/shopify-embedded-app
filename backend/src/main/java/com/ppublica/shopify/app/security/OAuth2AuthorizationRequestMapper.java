package com.ppublica.shopify.app.security;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Set;

public class OAuth2AuthorizationRequestMapper {

    public OAuth2AuthorizationRequest toOAuth2AuthorizationRequest(OAuth2AuthorizationRequestDTO dto) {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(dto.getAuthorizationUri())
                .clientId(dto.getClientId())
                .redirectUri(dto.getRedirectUri())
                .scopes(dto.getScopes())
                .state(dto.getState())
                .authorizationRequestUri(dto.getAuthorizationRequestUri())
                .build();
    }

    public OAuth2AuthorizationRequestDTO toOAuth2AuthorizationDto(OAuth2AuthorizationRequest request) {
        return new OAuth2AuthorizationRequestDTO.Builder()
                    .authorizationUri(request.getAuthorizationUri())
                    .clientId(request.getClientId())
                    .redirectUri(request.getRedirectUri())
                    .scopes(request.getScopes())
                    .state(request.getState())
                    .authorizationRequestUri(request.getAuthorizationRequestUri())
                    .build();
    }
}
