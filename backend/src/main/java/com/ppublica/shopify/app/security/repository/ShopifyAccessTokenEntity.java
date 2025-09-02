package com.ppublica.shopify.app.security.repository;

import java.time.LocalDateTime;

public record ShopifyAccessTokenEntity(String shop, String access_token, String scope, LocalDateTime date_created) {}

