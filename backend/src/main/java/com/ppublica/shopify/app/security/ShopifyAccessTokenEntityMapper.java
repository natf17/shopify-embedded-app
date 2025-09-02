package com.ppublica.shopify.app.security;

import com.ppublica.shopify.app.security.repository.ShopifyAccessTokenEntity;

public class ShopifyAccessTokenEntityMapper {
    public ShopifyAccessTokenEntity toShopifyAccessTokenEntity(ShopifyAccessToken model) {
        return new ShopifyAccessTokenEntity(model.shop(), model.access_token(), model.scope(), model.date_created());
    }

    public ShopifyAccessToken toShopifyAccessToken(ShopifyAccessTokenEntity entity) {
        return new ShopifyAccessToken(entity.shop(), entity.access_token(), entity.scope(), entity.date_created());
    }
}
