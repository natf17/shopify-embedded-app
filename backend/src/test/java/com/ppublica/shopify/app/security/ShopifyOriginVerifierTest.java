package com.ppublica.shopify.app.security;

import java.util.TreeMap;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ShopifyOriginVerifierTest {

    private ShopifyOriginVerifier verifier  = new ShopifyOriginVerifier("secret");

    @Test
    void toQueryString_shouldReturnQueryString_whenFullMap() {
        TreeMap<String, String[]> queryStringMap = new TreeMap<>();
        queryStringMap.put("code", new String[]{"0907"});
        queryStringMap.put("shop", new String[]{"shop.myshopify.com"});
        queryStringMap.put("state", new String[]{"0.63"});
        queryStringMap.put("timestamp", new String[]{"13"});

        assertEquals("code=0907&shop=shop.myshopify.com&state=0.63&timestamp=13", verifier.toQueryString(queryStringMap));

    }

    @Test
    void isHmacEquals_shouldReturnTrue_whenCorrectHash() {

    }
}
