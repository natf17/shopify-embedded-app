package com.ppublica.shopify.app.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Optional;
import java.util.Set;

/*
 * populates the ShopifyRequestAuthenticationToken with token information, if it is found.
 */
public class ShopifyRequestAuthenticationProvider implements AuthenticationProvider  {
    private final ShopifyOriginVerifier shopifyOriginVerifier;
    private final AccessTokenService accessTokenService;

    public ShopifyRequestAuthenticationProvider(AccessTokenService accessTokenService, ShopifyOriginVerifier shopifyOriginVerifier) {
        this.shopifyOriginVerifier = shopifyOriginVerifier;
        this.accessTokenService = accessTokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ShopifyRequestAuthenticationToken shopifyRequestAuthentication = (ShopifyRequestAuthenticationToken) authentication;

        String queryString = (String) shopifyRequestAuthentication.getCredentials();


        if(!shopifyOriginVerifier.comesFromShopify(queryString)) {
            throw new BadCredentialsException("Request does not come from Shopify");
        }
        String shop = ShopifyUtils.resolveShopQueryParamFromQueryString(queryString);

        Optional<ShopifyAccessToken> accessToken = accessTokenService.accessTokenForShop(shop);

        OAuthTokenMetadata tokenMetadata;
        if (accessToken.isPresent()) {
            String scope = accessToken.get().scope();
            Set<String> scopeSet = ShopifyUtils.convertScope(scope);
            tokenMetadata = new OAuthTokenMetadata(true, scopeSet);
        } else {
            tokenMetadata = new OAuthTokenMetadata(false, null);
        }

        return ShopifyRequestAuthenticationToken.authenticated(UriUtils.getQueryParams(queryString), tokenMetadata);

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ShopifyRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
