package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.TreeMap;

public class ShopifyOriginVerifier {
    private static final String HMAC_KEY = "hmac";
    private static final String ALGORITHM = "HmacSHA256";
    private final String hmacSecret;

    public ShopifyOriginVerifier(String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    public boolean comesFromShopify(HttpServletRequest httpServletRequest) {

        // Remove the HMAC parameter from the query string
        Map<String, String[]> parameterMap = httpServletRequest.getParameterMap();
        String[] hmacValues = parameterMap.get(HMAC_KEY);

        if(hmacValues.length != 1) {
            return false;
        }

        String hmacValue = hmacValues[0];
        parameterMap.remove(HMAC_KEY);

        // the parameters must be sorted alphabetically
        TreeMap<String, String[]> sortedQueryStringMap = new TreeMap<>(parameterMap);

        String sortedQueryString = toQueryString(sortedQueryStringMap);

        return isHmacEquals(hmacValue, sortedQueryString);

    }

    String toQueryString(TreeMap<String, String[]> sortedQueryStringMap) {
        StringBuilder queryStringBuilder = new StringBuilder();
        for(String parameterName : sortedQueryStringMap.keySet()) {
            for(String parameterValue : sortedQueryStringMap.get(parameterName)) {
                queryStringBuilder.append(parameterName);
                queryStringBuilder.append("=");
                queryStringBuilder.append(parameterValue);
                queryStringBuilder.append("&");
            }
        }
        return queryStringBuilder.substring(0, queryStringBuilder.length() - 1);

    }

    boolean isHmacEquals(String expected, String message) {
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            sha256_HMAC.init(secret_key);
            byte[] rawHmac = sha256_HMAC.doFinal(message.getBytes(StandardCharsets.UTF_8));

            return MessageDigest.isEqual(expected.getBytes(), rawHmac);
        } catch(Exception ex) {
            throw new RuntimeException("Invalid hmac");
        }
    }
}
