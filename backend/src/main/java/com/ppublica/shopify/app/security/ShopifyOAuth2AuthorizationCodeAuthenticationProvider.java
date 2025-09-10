package com.ppublica.shopify.app.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.regex.Pattern;

/*
 * Custom AuthenticationProvider that uses OAuth2AuthorizationCodeAuthenticationProvider under the hood.
 * Before delegating to the Spring authentication provider, it:
 *  - creates a new ClientRegistration with a shop-specific token uri
 *  - verifies that the shop parameter (extracted from the redirectUri) is valid
 */
public class ShopifyOAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationCodeAuthenticationProvider authProvider;
    private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";
    private static final String INVALID_HMAC_PARAMETER_ERROR_CODE = "invalid_hmac_parameter";
    private static final String SHOP_PARAM_NAME = "shop";
    private static final Pattern shopNameRegex = Pattern.compile("^https?://[a-zA-Z0-9][a-zA-Z0-9\\-]*\\.myshopify\\.com/?");

   public ShopifyOAuth2AuthorizationCodeAuthenticationProvider(OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
        this.authProvider = new OAuth2AuthorizationCodeAuthenticationProvider(accessTokenResponseClient);
   }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

        String requestUri = authorizationCodeAuthenticationToken.getAuthorizationExchange().getAuthorizationResponse().getRedirectUri();
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(requestUri).build();
        MultiValueMap<String, String> queryParams = uriComponents.getQueryParams();
        String shop = queryParams.getFirst(SHOP_PARAM_NAME);

        if(!isShopNameValid(shop)) {
            throw new OAuth2AuthorizationException(new OAuth2Error(INVALID_HMAC_PARAMETER_ERROR_CODE));
        }

        OAuth2AuthorizationCodeAuthenticationToken customizedAuthToken = addShopNameToTokenUri(authorizationCodeAuthenticationToken, shop);

        return authProvider.authenticate(customizedAuthToken);

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return authProvider.supports(aClass);

    }

    protected OAuth2AuthorizationCodeAuthenticationToken addShopNameToTokenUri(OAuth2AuthorizationCodeAuthenticationToken authToken, String shop) {
        ClientRegistration clientRegistration = authToken.getClientRegistration();
        String genericTokenUri = clientRegistration.getProviderDetails().getTokenUri();

        Map<String, String> vars = Map.of("shop", shop);
        String tokenUri = UriComponentsBuilder.fromUriString(genericTokenUri)
                .buildAndExpand(vars)
                .toUriString();

        ClientRegistration newClientRegistration = ClientRegistration.withClientRegistration(authToken.getClientRegistration())
                                                        .tokenUri(tokenUri)
                                                        .build();

        return new OAuth2AuthorizationCodeAuthenticationToken(newClientRegistration,
                                        authToken.getAuthorizationExchange());
    }


    protected boolean isShopNameValid(String shop) {
        return shopNameRegex.matcher(shop).matches();
    }
}
