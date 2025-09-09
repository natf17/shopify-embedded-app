package com.ppublica.shopify.app.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

// see https://github.com/spring-projects/spring-security/blob/main/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/authentication/OAuth2AuthorizationCodeAuthenticationProvider.java
public class ShopifyOAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        /*


        If you aren't using a library, then make sure that you verify the following:

IMPLEMENTED: The nonce is the same one that your app provided to Shopify when asking for permission.
TODO: Additionally, the signed cookie that you set when asking for permission is present and its value equals the nonce value in the state parameter.
TODO: The hmac is valid and signed by Shopify.
TODO: The shop parameter is a valid shop hostname, ends with myshopify.com, and doesn't contain characters other than letters (a-z), numbers (0-9), periods, and hyphens.
You can use a regular expression to confirm that the hostname is valid. In the following example, the regular expression matches the hostname form of https://{shop}.myshopify.com/:
         */



        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean supports(Class<?> aClass) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
