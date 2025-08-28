package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;

public class ShopifyOriginVerifier {

    public boolean comesFromShopify(HttpServletRequest httpServletRequest) {
        return false;
    }
}
