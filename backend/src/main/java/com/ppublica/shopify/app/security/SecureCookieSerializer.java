package com.ppublica.shopify.app.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SecureCookieSerializer {
    private final OAuth2AuthorizationRequestMapper dtoMapper;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String secret;
    private static final String ALGORITHM = "HmacSHA256";
    private static final int maxAgeDefault = 100;

    public SecureCookieSerializer(String secret, String clientRegistrationId) {
        this.secret = secret;
        this.dtoMapper = new OAuth2AuthorizationRequestMapper(clientRegistrationId);
    }

    protected OAuth2AuthorizationRequest deserializeAsOAuth2AuthorizationRequest(Cookie signedCookie) {
        String signedCookieValue = signedCookie.getValue();
        if(signedCookieValue == null || signedCookieValue.isEmpty()) {
            return null;
        }

        byte[] rawCookieValueBytes = Base64.getUrlDecoder().decode(signedCookieValue);
        String rawCookieValue = new String(rawCookieValueBytes, StandardCharsets.UTF_8);

        int indexOfSeparator = rawCookieValue.lastIndexOf("|");
        String encodedAuthorizationRequestDto = rawCookieValue.substring(0, indexOfSeparator);
        String encodedSignature = rawCookieValue.substring(indexOfSeparator + 1);

        byte[] oAuthRequestDtoBytes = Base64.getUrlDecoder().decode(encodedAuthorizationRequestDto);
        byte[] rawHmac = Base64.getUrlDecoder().decode(encodedSignature);

        try {
            byte[] expectedRawHmac = sign(oAuthRequestDtoBytes);

            if(!MessageDigest.isEqual(expectedRawHmac, rawHmac)) {
                throw new ShopifySecurityException();
            }

            OAuth2AuthorizationRequestDTO authorizationRequestDto = objectMapper.readValue(oAuthRequestDtoBytes, OAuth2AuthorizationRequestDTO.class);

            return dtoMapper.toOAuth2AuthorizationRequest(authorizationRequestDto);

        } catch (Exception ex) {
            throw new ShopifySecurityException();
        }

    }

    // if authorizationRequest is null, this method returns an "empty cookie"
    protected Cookie serializeAsCookie(OAuth2AuthorizationRequest authorizationRequest, String cookieName) {
        if(authorizationRequest == null) {
            return createCookie(cookieName, null,0);
        }
        try {
            OAuth2AuthorizationRequestDTO authorizationRequestDto = dtoMapper.toOAuth2AuthorizationDto(authorizationRequest);
            byte[] oAuthRequestBytes = objectMapper.writeValueAsBytes(authorizationRequestDto);
            byte[] rawHmac = sign(oAuthRequestBytes);

            String encodedAuthorizationRequestDto = Base64.getUrlEncoder().withoutPadding().encodeToString(oAuthRequestBytes);
            String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(rawHmac);

            String rawCookieValue = encodedAuthorizationRequestDto + "|" + encodedSignature;
            String encodedCookieValue = Base64.getUrlEncoder().withoutPadding().encodeToString(rawCookieValue.getBytes(StandardCharsets.UTF_8));

            return createCookie(cookieName, encodedCookieValue, maxAgeDefault);

        } catch(Exception ex) {
            throw new ShopifySecurityException();
        }

    }

    private Cookie createCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);

        return cookie;
    }

    private byte[] sign(byte[] value) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        sha256_HMAC.init(secret_key);
        return sha256_HMAC.doFinal(value);
    }
}
