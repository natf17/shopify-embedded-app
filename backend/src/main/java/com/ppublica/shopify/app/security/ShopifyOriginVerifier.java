package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;
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

public class ShopifyOriginVerifier {
    private static final String HMAC_KEY = "hmac";
    private static final String SHOP_PARAM_NAME = "shop";
    private static final String ALGORITHM = "HmacSHA256";
    private final String hmacSecret;

    public ShopifyOriginVerifier(String hmacSecret) {
        this.hmacSecret = hmacSecret;
    }

    // also adds shop to request attribute if successful
    public boolean comesFromShopify(MultiValueMap<String, String> queryParams) {

        // the parameters must be sorted alphabetically
        TreeMap<String, List<String>> sortedQueryStringMap = new TreeMap<>(queryParams);

        // Remove the HMAC parameter from the query string
        List<String> hmacValues = sortedQueryStringMap.get(HMAC_KEY);

        if(hmacValues == null || hmacValues.size() != 1) {
            return false;
        }

        String hmacValue = hmacValues.getFirst();
        sortedQueryStringMap.remove(HMAC_KEY);


        String sortedQueryString = toQueryString(sortedQueryStringMap);

        return isHmacEquals(hmacValue, sortedQueryString);


    }

    String toQueryString(TreeMap<String, List<String>> sortedQueryStringMap) {
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
