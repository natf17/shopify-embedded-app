package com.ppublica.shopify.app.security;

public class AccessTokenService {
    private final ShopAccessTokenRepository shopAccessTokenRepository;

    public AccessTokenService(ShopAccessTokenRepository shopAccessTokenRepository) {
        this.shopAccessTokenRepository = shopAccessTokenRepository;
    }
    public ShopifyAccessToken accessTokenForShop(String shop) {
        return shopAccessTokenRepository.accessTokenForShop(shop);
    }
}
