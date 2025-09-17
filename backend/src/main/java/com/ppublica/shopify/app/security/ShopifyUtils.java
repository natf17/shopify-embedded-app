package com.ppublica.shopify.app.security;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ShopifyUtils {
    public static String SHOP_QUERY_PARAM = "shop";
    public static String SHOPIFY_SCOPE_DELIMITER = ",";

    public static Set<String> convertScope(String scope) {
        return convertScope(scope, SHOPIFY_SCOPE_DELIMITER);
    }

    public static Set<String> convertScope(String scope, String delimiter) {
        String[] scopeArray = scope.split(delimiter);
        return new HashSet<>(Arrays.asList(scopeArray));
    }

    public static boolean areScopesSatisfied(Set<String> required, Set<String> actual) {

    }


}
