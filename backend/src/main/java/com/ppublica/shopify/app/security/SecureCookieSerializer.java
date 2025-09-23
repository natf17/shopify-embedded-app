package com.ppublica.shopify.app.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SecureCookieSerializer {
    private static final Logger log = LoggerFactory.getLogger(CookieOAuth2AuthorizationRequestRepository.class);
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
            log.error("The cookie value is null or empty");
            return null;
        }

        log.debug("Base64 decoding the entire cookie value");
        byte[] rawCookieValueBytes = Base64.getUrlDecoder().decode(signedCookieValue);
        log.debug("Encoding the byte[] into UTF-8 string to process...");
        String rawCookieValue = new String(rawCookieValueBytes, StandardCharsets.UTF_8);

        log.debug("Split the string into the authorization request and signature");
        int indexOfSeparator = rawCookieValue.lastIndexOf("|");
        String encodedAuthorizationRequestDto = rawCookieValue.substring(0, indexOfSeparator);
        String encodedSignature = rawCookieValue.substring(indexOfSeparator + 1);

        log.debug("Base-64 decode the authorization request");
        byte[] oAuthRequestDtoBytes = Base64.getUrlDecoder().decode(encodedAuthorizationRequestDto);
        log.debug("Base-64 decode the signature");
        byte[] rawHmac = Base64.getUrlDecoder().decode(encodedSignature);

        try {
            log.debug("Signing the authorization request");
            byte[] expectedRawHmac = sign(oAuthRequestDtoBytes);

            log.debug("Comparing the signature of the authorization request with the one provided in the cookie");
            if(!MessageDigest.isEqual(expectedRawHmac, rawHmac)) {
                log.error("The signatures are different!");
                throw new ShopifySecurityException();
            }

            log.debug("Converting the byte[] authorization request to an object");
            OAuth2AuthorizationRequestDTO authorizationRequestDto = objectMapper.readValue(oAuthRequestDtoBytes, OAuth2AuthorizationRequestDTO.class);

            return dtoMapper.toOAuth2AuthorizationRequest(authorizationRequestDto);

        } catch (Exception ex) {
            throw new ShopifySecurityException();
        }

    }

    // if authorizationRequest is null, this method returns an "empty cookie"
    protected Cookie serializeAsCookie(OAuth2AuthorizationRequest authorizationRequest, String cookieName) {
        if(authorizationRequest == null) {
            log.debug("Creating an empty cookie");
            return createCookie(cookieName, null,0);
        }
        try {
            OAuth2AuthorizationRequestDTO authorizationRequestDto = dtoMapper.toOAuth2AuthorizationDto(authorizationRequest);
            log.debug("Converting authorization request to byte[]");
            byte[] oAuthRequestBytes = objectMapper.writeValueAsBytes(authorizationRequestDto);

            log.debug("Signing...");
            byte[] rawHmac = sign(oAuthRequestBytes);

            log.debug("Base-64 encoding the authorization request");
            String encodedAuthorizationRequestDto = Base64.getUrlEncoder().withoutPadding().encodeToString(oAuthRequestBytes);

            log.debug("Base-64 encoding the signature");
            String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(rawHmac);

            log.debug("Concatenating the authorization request and the signature");
            String rawCookieValue = encodedAuthorizationRequestDto + "|" + encodedSignature;

            log.debug("Base64 encoding the entire cookie value");
            String encodedCookieValue = Base64.getUrlEncoder().withoutPadding().encodeToString(rawCookieValue.getBytes(StandardCharsets.UTF_8));

            log.debug("Returning the new cookie");
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
