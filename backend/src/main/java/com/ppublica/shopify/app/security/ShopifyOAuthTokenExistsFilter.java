package com.ppublica.shopify.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/*
 * This filter checks if a valid access token already exists for this shop,
 * and saves this information in attribute in the request. The attribute is false if any
 * of the following is true:
 *  - (A) no access token exists
 *  - (B) an access token exists but the scopes don't match what the app needs
 *
 * The token is deleted if (B) is true.
 */
public class ShopifyOAuthTokenExistsFilter extends OncePerRequestFilter {
    public static final String ACCESSTOKEN_EXISTS_ATTRIBUTE = "valid_accesstoken_exists";
    private final AccessTokenService accessTokenService;

    public ShopifyOAuthTokenExistsFilter(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String shop = request.getParameter("shop");

        Optional<ShopifyAccessToken> accessToken = accessTokenService.accessTokenForShop(shop);


        if(accessToken.isEmpty()) {
            request.setAttribute(ACCESSTOKEN_EXISTS_ATTRIBUTE, false);
            filterChain.doFilter(request, response);
            return;
        }

        if(isTokenValid(accessToken.get())) {
            request.setAttribute(ACCESSTOKEN_EXISTS_ATTRIBUTE, true);
        } else {
            accessTokenService.deleteToken(shop);
            request.setAttribute(ACCESSTOKEN_EXISTS_ATTRIBUTE, false);
        }

        filterChain.doFilter(request, response);
    }

    boolean isTokenValid(ShopifyAccessToken accessToken) {
        return false;
    }
}
