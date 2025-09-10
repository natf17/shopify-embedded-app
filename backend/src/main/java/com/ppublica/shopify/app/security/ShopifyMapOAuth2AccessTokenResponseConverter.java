package com.ppublica.shopify.app.security;

import org.jspecify.annotations.Nullable;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/*
 * A converter that delegates to the default token response converter, but modifies the scopes to use "," instead of " "
 * as the delimiter.
 */
public class ShopifyMapOAuth2AccessTokenResponseConverter implements Converter<Map<String, Object>, OAuth2AccessTokenResponse> {
    private final DefaultMapOAuth2AccessTokenResponseConverter defaultConverter = new DefaultMapOAuth2AccessTokenResponseConverter();
    private final String shopifyDelimiter = ",";
    private final String defaultDelimiter = " ";

    @Override
    public @Nullable OAuth2AccessTokenResponse convert(Map<String, Object> source) {
        OAuth2AccessTokenResponse response = defaultConverter.convert(source);

        return withCorrectedScopes(response);
    }

    protected OAuth2AccessTokenResponse withCorrectedScopes(OAuth2AccessTokenResponse original) {
        Set<String> originalScopeSet = original.getAccessToken().getScopes();

        if(originalScopeSet.isEmpty()) {
            return original;
        }

        String originalScopeString = String.join(defaultDelimiter, originalScopeSet);

        Set<String> correctedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(originalScopeString, shopifyDelimiter)));

        return OAuth2AccessTokenResponse.withResponse(original)
                .scopes(correctedScopes)
                .build();
    }

}
