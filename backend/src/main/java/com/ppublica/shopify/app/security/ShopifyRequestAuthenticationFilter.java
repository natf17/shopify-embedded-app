package com.ppublica.shopify.app.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
 * This filter authenticates requests to paths that should come from Shopify.
 *
 */
public class ShopifyRequestAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(ShopifyRequestAuthenticationFilter.class);
    private final RequestMatcher path;
    private final AuthenticationManager authenticationManager;
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    public ShopifyRequestAuthenticationFilter(AuthenticationManager authenticationManager, RequestMatcher path) {
        this.path = path;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        log.debug("In ShopifyRequestAuthenticationFilter---");
        if(!requiresVerification(httpServletRequest)) {
            log.debug("ShopifyRequestAuthenticationFilter--- not matched");

            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }
        log.debug("ShopifyRequestAuthenticationFilter--- matched");

        try {
            ShopifyRequestAuthenticationToken authentication = ShopifyRequestAuthenticationToken.unauthenticated(httpServletRequest.getQueryString());
            ShopifyRequestAuthenticationToken authResult = (ShopifyRequestAuthenticationToken) authenticationManager.authenticate(authentication);
            SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authResult);
            this.securityContextHolderStrategy.setContext(context);
            this.securityContextRepository.saveContext(context, httpServletRequest, httpServletResponse);
            log.debug("Authenticated");

        } catch (AuthenticationException ex) {
            log.debug("Authentication failed. We assume the app is not embedded");

        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private boolean requiresVerification(HttpServletRequest httpServletRequest) {
        return this.path.matches(httpServletRequest);
    }
}
