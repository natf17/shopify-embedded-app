package com.ppublica.shopify.app.security;

import java.time.LocalDateTime;

public record ShopifyAccessToken(String shop, String access_token, String scope, LocalDateTime date_created) {}
