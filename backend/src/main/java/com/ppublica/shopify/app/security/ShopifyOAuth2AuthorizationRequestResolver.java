package com.ppublica.shopify.app.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

import static com.ppublica.shopify.app.security.ShopifyUtils.SHOP_QUERY_PARAM;

/*
 * This class updates the authorization uri and authorization request uri to ensure that
 * - only the query parameters required by Shopify are included (see OAuth2AuthorizationRequest.Builder.getParameters())
 *   (the grant_options[] query param is omitted since we need an offline access token)
 * - the {shop} path variable is resolved and inserted dynamically
 *
 * This class also decides whether to initiate the OAuth flow. It will attempt to initiate the flow if any of the
 * following is true:
 *  - (A) the user is unauthenticated (the request does not come from shopify)
 *  - (B) the user is authenticated but no access token exists
 *  - (B) the user is authenticated and an access token exists but the scopes don't match what the app needs
 *
 * This resolver depends on ShopifyRequestAuthenticationToken being in the SecurityContext if the token exists.
 *
 *  Returning null from resolve() bypasses the OAuth redirect in OAuth2AuthorizationRequestRedirectFilter.
 */
public class ShopifyOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private static final Logger log = LoggerFactory.getLogger(ShopifyOAuth2AuthorizationRequestResolver.class);
    private final DefaultOAuth2AuthorizationRequestResolver delegate;
    private final ClientRegistration shopifyClientRegistration;

    public ShopifyOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
                                                     String authorizationRequestBaseUri, String registrationId) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
        this.delegate.setAuthorizationRequestCustomizer(customizer -> customizer
                .parameters(params -> params.remove(OAuth2ParameterNames.RESPONSE_TYPE))
                .authorizationRequestUri("/authorization")); // we will change later when we customize the OAuth2AuthorizationRequest
        this.shopifyClientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);

    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        if(!shouldInitiateOAuthFlow(request)) {
            log.debug("Will not initiate OAuth flow, returning null");
            return null;
        }

        log.debug("Initiate the OAuth flow");
        OAuth2AuthorizationRequest original = delegate.resolve(request);
        return customize(original, request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        if(!shouldInitiateOAuthFlow(request)) {
            log.debug("Will not initiate OAuth flow, returning null");
            return null;
        }

        log.debug("Initiate the OAuth flow");
        OAuth2AuthorizationRequest original = delegate.resolve(request, clientRegistrationId);

        return customize(original, request);
    }

    /*
     * Substitutes shop name into {shop} path variable in the existing authorization request and authorization uris
     *
     */
    protected OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest original, HttpServletRequest request) {
        String shop = resolveShopName(request);
        log.debug("Customizing the OAuth2AuthorizationRequest with shop name: " + shop);
        if(shop == null || shop.isEmpty()) {
            throw new ShopifySecurityException();
        }

        Map<String, String> vars = Map.of("shop", shop);
        String authorizationUriTemplate = shopifyClientRegistration.getProviderDetails().getAuthorizationUri();
        String authorizationUri = UriComponentsBuilder
                .fromUriString(authorizationUriTemplate)
                .buildAndExpand(vars)
                .toUri()
                .toString();

        log.debug("Adding authorization uri: " + authorizationUri);

        OAuth2AuthorizationRequest customizedRequest =  OAuth2AuthorizationRequest.from(original)
                .authorizationUri(authorizationUri)
                .build();

        log.debug("OAuth2AuthorizationRequest built with [authReqUri=" + customizedRequest.getAuthorizationRequestUri()
                    + "], [redirectUri = " + customizedRequest.getRedirectUri() + "]");

        return customizedRequest;
    }

     protected boolean shouldInitiateOAuthFlow(HttpServletRequest request) {

        ShopifyRequestAuthenticationToken auth = (ShopifyRequestAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();

         if(auth == null || !auth.isAuthenticated()) {
             log.debug("No Authentication found");
            return true;
         }

         ShopDetails shopDetails = (ShopDetails)auth.getPrincipal();

         if(!shopDetails.tokenMetadata().doesOAuthTokenExist()) {
             log.debug("Authenticated but no OAuth token");
             return true;
         }

         if(!ShopifyUtils.areScopesSatisfied(shopifyClientRegistration.getScopes(), shopDetails.tokenMetadata().scope())) {
             log.debug("Authenticated and has OAuth token, but the scopes don't match");
             return true;
         }

        return false;

    }

    protected String resolveShopName(HttpServletRequest request) {
        ShopifyRequestAuthenticationToken auth = (ShopifyRequestAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();

        if(auth != null) {
            ShopDetails shopDetails = (ShopDetails)auth.getPrincipal();
            log.debug("Obtaining shop from Authentication");
            return shopDetails.shop();
        }

        // fall back to any request param; maybe the request is from a non-embedded request
        log.debug("Resolving shop param");
        return ShopifyUtils.resolveShopParamFromRequest(request);


    }

}
