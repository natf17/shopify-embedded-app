package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static com.ppublica.shopify.app.security.ShopifyUtils.HMAC_QUERY_PARAM;
import static com.ppublica.shopify.app.security.ShopifyUtils.SHOP_QUERY_PARAM;

public class ShopifyOriginVerifier {
    private static final Logger log = LoggerFactory.getLogger(ShopifyOriginVerifier.class);
    private static final String HMAC_KEY = HMAC_QUERY_PARAM;
    private static final String SHOP_PARAM_NAME = SHOP_QUERY_PARAM;
    private static final String ALGORITHM = "HmacSHA256";
    private final String hmacSecret;

    public ShopifyOriginVerifier(String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    public boolean comesFromShopify(String queryString) {
        MultiValueMap<String, String> queryParamMap = UriUtils.getQueryParams(queryString);

        // the parameters must be sorted alphabetically
        TreeMap<String, List<String>> sortedQueryStringMap = new TreeMap<>(queryParamMap);

        // Remove the HMAC parameter from the query string
        List<String> hmacValues = sortedQueryStringMap.get(HMAC_KEY);

        if(hmacValues == null || hmacValues.size() != 1) {
            log.debug("Did not find exactly one hmac query parameter");
            return false;
        }

        String hmacValue = hmacValues.getFirst();
        sortedQueryStringMap.remove(HMAC_KEY);

        String sortedQueryString = toQueryString(sortedQueryStringMap);

        return isHmacEquals(hmacValue, sortedQueryString);


    }

    String toQueryString(TreeMap<String, List<String>> sortedQueryStringMap) {
        log.debug("Sorting the query string... the query params will be url-decoded here");
        StringBuilder queryStringBuilder = new StringBuilder();
        for(String parameterName : sortedQueryStringMap.keySet()) {
            for(String parameterValue : sortedQueryStringMap.get(parameterName)) {
                queryStringBuilder.append(decodeQueryParam(parameterName));
                queryStringBuilder.append("=");
                queryStringBuilder.append(decodeQueryParam(parameterValue));
                queryStringBuilder.append("&");
            }
        }
        return queryStringBuilder.substring(0, queryStringBuilder.length() - 1);

    }

    /*
     * Assumptions/preconditions:
     * - To get byte[] of human-readable string (like query string), convert characters into their UTF-8 byte representation
     * - The expected parameter is a hex-encoded byte[].
     *
     * To perform the comparison, the message parameter is
     *  1. -> encoded to byte[] UTF-8 representation
     *  2. -> signed
     *  3. -> hex encoded
     *
     *  Both strings (expected and message) are UTF-8 decoded to byte[] to perform the comparison
     *
     */
    boolean isHmacEquals(String expected, String message) {
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            sha256_HMAC.init(secret_key);
            byte[] rawHmacOfMessage = sha256_HMAC.doFinal(message.getBytes(StandardCharsets.UTF_8));
            String hexHmacOfMessage = toHex(rawHmacOfMessage);

            return MessageDigest.isEqual(expected.getBytes(), hexHmacOfMessage.getBytes());
        } catch(Exception ex) {
            log.info("Invalid hmac: {}", ex.getMessage());
            throw new ShopifySecurityException();
        }
    }

    private String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private static String decodeQueryParam(String value) {
        return UriUtils.urlDecode(value);
    }

}
