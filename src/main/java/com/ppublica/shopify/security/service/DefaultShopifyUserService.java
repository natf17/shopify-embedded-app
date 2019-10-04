package com.ppublica.shopify.security.service;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.ppublica.shopify.security.web.ShopifyOAuth2AuthorizationRequestResolver;

/*
 * Replaces DefaultOAuth2UserService.
 * 
 * This class is called by OAuth2LoginAuthenticationProvider when creating the OAuth2LoginAuthenticationToken.
 * 
 * Since the default OAuth2LoginAuthenticationProvider sets the OAuth2User as the principal,
 * this class instantiates a ShopifyStore that contains:
 * 	1. the shop name as the "name' of the principal
 * 	2. the api key as an additional attribute
 * 	3. the the access token as an additional attribute
 * 
 * Note: the OAuth2UserRequest has the shop parameter because our custom ShopifyAuthorizationCodeTokenResponseClient
 * stored it in the OAuth2AccessTokenResponse, which was used to create the OAuth2UserRequest.
 * 
 */

public class DefaultShopifyUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	
	
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		Object shopName = userRequest.getAdditionalParameters().get(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN);
		String apiKey = userRequest.getClientRegistration().getClientId();
		
		Set<String> scopes = userRequest.getAccessToken().getScopes();
		Collection<GrantedAuthority> authorities = null;
		if(scopes != null) {
			authorities = scopes.stream()
									.map(scope -> new SimpleGrantedAuthority(scope))
									.collect(Collectors.toList());
		}
		
		return new ShopifyStore((String)shopName, userRequest.getAccessToken().getTokenValue(), apiKey, authorities);
	}
	
}
