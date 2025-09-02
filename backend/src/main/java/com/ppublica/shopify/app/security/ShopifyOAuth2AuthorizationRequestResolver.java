package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

public class ShopifyOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver delegate;

    public ShopifyOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                                     String authorizationRequestBaseUri) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
        this.delegate.setAuthorizationRequestCustomizer(customizer -> customizer
                .parameters(params -> params.remove(OAuth2ParameterNames.RESPONSE_TYPE)));

    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        if(oauthTokenExists()) {
            return null;
        }

        OAuth2AuthorizationRequest original = delegate.resolve(request);
        return customize(original, request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        if(oauthTokenExists()) {
            return null;
        }

        OAuth2AuthorizationRequest original = delegate.resolve(request, clientRegistrationId);

        return customize(original, request);
    }

    // gets shop name from request attribute that was set by ShopifyInstallationRequestFilter
    // and substitutes into {shop} path variable in the existing authorization request and authorization uris
    OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest original, HttpServletRequest request) {
        String shop = (String)request.getAttribute(ShopifyInstallationRequestFilter.SHOP_NAME_ATTR);
        Map<String, String> vars = Map.of("shop", shop);
        String authorizationRequestUri = UriComponentsBuilder.fromUriString(original.getAuthorizationRequestUri())
                .buildAndExpand(vars)
                .toUriString();

        String authorizationUri = UriComponentsBuilder.fromUriString(original.getAuthorizationUri())
                .buildAndExpand(vars)
                .toUriString();

        return OAuth2AuthorizationRequest.from(original)
                .authorizationRequestUri(authorizationRequestUri)
                .authorizationUri(authorizationUri)
                .build();
    }

     boolean oauthTokenExists() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if(auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            return true;
        }

        return false;
    }

}
