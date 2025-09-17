package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class UriUtils {
    static String fullRequestUrl(HttpServletRequest request) {
        return request.getRequestURL().toString() + "?" + request.getQueryString();
    }
    static MultiValueMap<String, String> getQueryParams(String queryString) {
        String dummyUrl = "https://dummy?";
        String uriString = dummyUrl + queryString;
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(uriString).build();
        return uriComponents.getQueryParams();
    }
}
