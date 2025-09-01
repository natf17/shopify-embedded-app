package com.ppublica.shopify.app.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Value("${ppublica.shopify.app.client-secret}")
    private String clientSecret;

    @Value("${ppublica.shopify.app.path-requiring-shopify-origin-verification:/**}")
    private String pathRequiringShopifyOriginVerification;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ShopifyInstallationRequestFilter shopifyInstallationRequestFilter, ShopifyOAuth2AuthorizationCodeGrantFilter shopifyOAuth2AuthorizationCodeGrantFilter) throws Exception {
        http.authorizeHttpRequests( authorize -> authorize
                .anyRequest().authenticated()
        )
            .oauth2Client(oauth2Client -> oauth2Client
                        .authorizationCodeGrant(authCodeGrant -> authCodeGrant
                                .authorizationRequestResolver(new ShopifyOAuth2AuthorizationRequestResolver())
                        )
            )
            .addFilterBefore(shopifyInstallationRequestFilter, OAuth2AuthorizationRequestRedirectFilter.class)
            .addFilterBefore(shopifyOAuth2AuthorizationCodeGrantFilter, OAuth2AuthorizationCodeGrantFilter.class);


        return http.build();

    }

    @Bean
    public ShopifyOriginVerifier shopifyOriginVerifier() {
        return new ShopifyOriginVerifier(clientSecret);
    }

    @Bean
    public ShopifyInstallationRequestFilter shopifyInstallationRequestFilter() {
        return new ShopifyInstallationRequestFilter(PathPatternRequestMatcher.pathPattern(pathRequiringShopifyOriginVerification));
    }

    @Bean
    public ShopifyOAuth2AuthorizationCodeGrantFilter shopifyOAuth2AuthorizationCodeGrantFilter(AuthenticationManager authManager) {
        return new ShopifyOAuth2AuthorizationCodeGrantFilter(authManager);
    }

    @Bean
    public AuthenticationProvider shopifyOAuth2AuthorizationCodeAuthenticationProvider() {
        return new ShopifyOAuth2AuthorizationCodeAuthenticationProvider();
    }
}
