package com.ppublica.shopify.app.security;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ShopifyInstallationRequestFilter extends OncePerRequestFilter {

    public static final String SHOP_NAME_ATTR = "security_shopify_shop_name";

    private ShopifyOriginVerifier shopifyOriginVerifier;
    private final RequestMatcher path;

    public ShopifyInstallationRequestFilter(ShopifyOriginVerifier shopifyOriginVerifier, RequestMatcher path) {
        this.shopifyOriginVerifier = shopifyOriginVerifier;
        this.path = path;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        if(requiresVerification(httpServletRequest)) {
            if(shopifyOriginVerifier.comesFromShopify(httpServletRequest)) {
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            } else {
                httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private boolean requiresVerification(HttpServletRequest httpServletRequest) {
        return this.path.matches(httpServletRequest);
    }
}
