package com.ppublica.shopify.app.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.MultiValueMap;

import java.util.Collection;
import java.util.Collections;

/*
 * In the context of authenticating Shopify requests, this is the Authentication object for both the pre-auth and post-auth stages.
 *
 * Pre-auth: contains only the query string
 * Post-auth: contains all properties except the queryString. The authorities collection is empty
 */
public class ShopifyRequestAuthenticationToken extends AbstractAuthenticationToken {
    private final ShopDetails shop;
    private String queryString;

    public ShopifyRequestAuthenticationToken(ShopDetails shop, String queryString, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.shop = shop;
        this.queryString = queryString;
    }

    @Override
    public Object getCredentials() {
        return this.queryString;
    }

    @Override
    public Object getPrincipal() {
        return this.shop;
    }

    @Override
    public void eraseCredentials() {
        this.queryString = null;
    }

    public static ShopifyRequestAuthenticationToken unauthenticated(String queryString) {
        return new ShopifyRequestAuthenticationToken(null, queryString, null);
    }

    public static ShopifyRequestAuthenticationToken authenticated(MultiValueMap<String, String> queryParamMap, OAuthTokenMetadata tokenMetadata) {
        String shop = queryParamMap.getFirst("shop");
        ShopifyRequestAuthenticationToken auth = new ShopifyRequestAuthenticationToken(new ShopDetails(shop, tokenMetadata), null, Collections.emptyList());
        auth.setAuthenticated(true);

        return auth;
    }



}
