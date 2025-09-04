package com.ppublica.shopify.app.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Arrays;
import java.util.Optional;

public class CookieOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private static final String OAUTH2_COOKIE_NAME = "Shopify_OAuth_Request";
    private SecureCookieSerializer cookieSerializer;

    public CookieOAuth2AuthorizationRequestRepository(SecureCookieSerializer cookieSerializer) {
        this.cookieSerializer = cookieSerializer;
    }
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return getOAuth2Cookie(request)
                .map(cookieSerializer::deserializeAsOAuth2AuthorizationRequest)
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if(authorizationRequest == null) {
            return;
        }

        Cookie cookie = cookieSerializer.serializeAsCookie(authorizationRequest, OAUTH2_COOKIE_NAME);
        saveOAuth2Cookie(cookie, response);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);

        if(authorizationRequest != null) {
            deleteOAuth2Cookie(response);
        }

        return authorizationRequest;
    }

    protected Optional<Cookie> getOAuth2Cookie(HttpServletRequest request) {
        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(OAUTH2_COOKIE_NAME))
                .findFirst();
    }

    protected void saveOAuth2Cookie(Cookie signedCookie, HttpServletResponse response) {
        response.addCookie(signedCookie);
    }

    protected void deleteOAuth2Cookie(HttpServletResponse response) {
        response.addCookie(cookieSerializer.serializeAsCookie(null, OAUTH2_COOKIE_NAME));
    }



}
