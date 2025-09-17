package com.ppublica.shopify.app.security;

/*
 * Represents the Principal when authenticating a request that comes from Shopify.
 */
public record ShopDetails(String shop, OAuthTokenMetadata tokenMetadata) {}
