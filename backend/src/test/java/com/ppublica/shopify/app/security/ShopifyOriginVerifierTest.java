package com.ppublica.shopify.app.security;

import java.util.List;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ShopifyOriginVerifierTest {

    private ShopifyOriginVerifier verifier  = new ShopifyOriginVerifier("secret");

    @Test
    void toQueryString_shouldReturnQueryString_whenFullMap() {
        TreeMap<String, List<String>> queryStringMap = new TreeMap<>();
        queryStringMap.put("code", List.of("0907"));
        queryStringMap.put("shop", List.of("shop.myshopify.com"));
        queryStringMap.put("state", List.of("0.63"));
        queryStringMap.put("timestamp", List.of("13"));

        assertEquals("code=0907&shop=shop.myshopify.com&state=0.63&timestamp=13", verifier.toQueryString(queryStringMap));

    }

}
