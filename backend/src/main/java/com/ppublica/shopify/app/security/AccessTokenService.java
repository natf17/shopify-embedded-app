package com.ppublica.shopify.app.security;

import com.ppublica.shopify.app.security.repository.ShopAccessTokenRepository;
import com.ppublica.shopify.app.security.repository.ShopifyAccessTokenEntity;

import java.util.Optional;

public class AccessTokenService {
    private final ShopAccessTokenRepository shopAccessTokenRepository;
    private final ShopifyAccessTokenEntityMapper entityMapper = new ShopifyAccessTokenEntityMapper();

    public AccessTokenService(ShopAccessTokenRepository shopAccessTokenRepository) {
        this.shopAccessTokenRepository = shopAccessTokenRepository;
    }

    public Optional<ShopifyAccessToken> accessTokenForShop(String shop) {
        Optional<ShopifyAccessTokenEntity> accessTokenEntity = shopAccessTokenRepository.accessTokenForShop(shop);
        if(accessTokenEntity.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(entityMapper.toShopifyAccessToken(accessTokenEntity.get()));
    }

    public void deleteToken(String shop) {
        shopAccessTokenRepository.deleteAccessToken(shop);
    }


}
