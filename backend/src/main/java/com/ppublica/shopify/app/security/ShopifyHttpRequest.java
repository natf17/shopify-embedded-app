package com.ppublica.shopify.app.security;

import com.nimbusds.jose.util.StandardCharset;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Base64;

public class ShopifyHttpRequest {
    private final HttpServletRequest request;
    private final String shop;
    private final String host;

    public ShopifyHttpRequest(HttpServletRequest request) {
        this.request = request;
        String uriString = request.getRequestURL().toString() + "?" + request.getQueryString();
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(uriString).build();
        MultiValueMap<String, String> queryParams = uriComponents.getQueryParams();
        this.shop = queryParams.getFirst("shop");
        this.host = queryParams.getFirst("host");
    }

    public String getShop() {
        return this.shop;
    }

    // Returns the host value as sent by Shopify: Base64-encoded, with padding removed
    public String getRawHost() {
        return this.host;
    }

    // Returns the decoded host value
    public String getBase64DecodedHost() {
        String paddedHostValue = checkAndRestorePadding(host);
        byte[] decodedBytes = Base64.getUrlDecoder().decode(paddedHostValue);

        return new String(decodedBytes, StandardCharset.UTF_8);
    }

    public HttpServletRequest getHttpServletRequest() {
        return this.request;
    }

    protected String checkAndRestorePadding(String input) {
        int currentPadding = 4 - input.length() % 4;
        int paddingNeeded = currentPadding % 4;

        return input + "=".repeat(paddingNeeded);
    }

}
