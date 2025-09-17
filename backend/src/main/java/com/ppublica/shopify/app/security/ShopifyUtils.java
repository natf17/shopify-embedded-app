package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ShopifyUtils {
    public static String SHOP_QUERY_PARAM = "shop";
    public static String EMBEDDED_QUERY_PARAM = "embedded";
    public static String HMAC_QUERY_PARAM = "hmac";
    public static String SHOPIFY_SCOPE_DELIMITER = ",";

    public static Set<String> convertScope(String scope) {
        return convertScope(scope, SHOPIFY_SCOPE_DELIMITER);
    }

    public static Set<String> convertScope(String scope, String delimiter) {
        String[] scopeArray = scope.split(delimiter);
        return new HashSet<>(Arrays.asList(scopeArray));
    }

    public static boolean areScopesSatisfied(Set<String> required, Set<String> actual) {
        return required.stream()
                .allMatch(scope -> actual.contains(scope) ||
                        actual.contains(scope.replaceFirst("read", "write")));
    }

    public static String resolveShopQueryParamFromQueryString(String queryString) {
        return resolveQueryParamFromQueryString(queryString, SHOP_QUERY_PARAM);
    }

    public static String resolveQueryParamFromQueryString(String queryString, String queryParamKey) {
        return UriUtils.getQueryParams(queryString).getFirst(queryParamKey);
    }

    public static String resolveShopQueryParamFromFullUri(String fullUri) {
        return resolveQueryParamFromFullUri(fullUri, SHOP_QUERY_PARAM);
    }

    public static String resolveQueryParamFromFullUri(String fullUri, String queryParamKey) {
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(fullUri).build();
        MultiValueMap<String, String> queryParams = uriComponents.getQueryParams();
        return queryParams.getFirst(queryParamKey);
    }

    public static String resolveShopParamFromRequest(HttpServletRequest request) {
        return request.getParameter(SHOP_QUERY_PARAM);
    }


}
