package com.ppublica.shopify.app.security;

import java.util.Set;

public record OAuthTokenMetadata(boolean doesOAuthTokenExist, Set<String> scope) {}
