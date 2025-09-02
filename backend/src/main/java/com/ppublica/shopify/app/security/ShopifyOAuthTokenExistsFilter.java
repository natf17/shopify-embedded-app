package com.ppublica.shopify.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ShopifyOAuthTokenExistsFilter extends OncePerRequestFilter {
    public static final String ACCESSTOKEN_EXISTS_ATTRIBUTE = "valid_accesstoken_exists";
    private final AccessTokenService accessTokenService;

    public ShopifyOAuthTokenExistsFilter(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String shop = request.getParameter("shop");

        ShopifyAccessToken accessToken = accessTokenService.accessTokenForShop(shop);

        request.setAttribute(ACCESSTOKEN_EXISTS_ATTRIBUTE, checkToken(accessToken));

        filterChain.doFilter(request, response);

    }

    boolean checkToken(ShopifyAccessToken accessToken) {
        return false;
    }
}
