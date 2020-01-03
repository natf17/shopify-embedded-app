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


/**
 * An implementation of OAuth2UserService that builds a ShopifyStore. This class is called by OAuth2LoginAuthenticationProvider 
 * when creating the OAuth2LoginAuthenticationToken. It replaces DefaultOAuth2UserService.
 * 
 * <p>Since the default OAuth2LoginAuthenticationProvider sets the OAuth2User as the principal, this class 
 * instantiates a ShopifyStore that contains:</p>
 * <ol>
 * 	<li>the full shop domain as the "name" of the principal</li>
 * 	<li>the api key as an additional attribute</li>
 * 	<li>the the access token as an additional attribute</li>
 * </ol>
 * 
 * @author N F
 * @see org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider
 * 
 */
public class DefaultShopifyUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	
	
	/**
	 * Build a ShopifyStore using the given OAuth2UserRequest. It expects the OAuth2UserRequest to have the full
	 * shop domain as an additional attribute, with the key value 
	 * ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN. ShopifyAuthorizationCodeTokenResponseClient
	 * should have stored it there.
	 * 
	 * @see com.ppublica.shopify.security.web.ShopifyAuthorizationCodeTokenResponseClient
	 */
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
