package com.ppublica.shopify.app.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

// see https://github.com/spring-projects/spring-security/blob/main/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/web/OAuth2AuthorizationCodeGrantFilter.java
public class ShopifyOAuth2AuthorizationCodeGrantFilter extends OncePerRequestFilter {

   public ShopifyOAuth2AuthorizationCodeGrantFilter(AuthenticationManager manager) {

   }
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        throw new UnsupportedOperationException("Not implemented");
    }
}
