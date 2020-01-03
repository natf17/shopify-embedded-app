package com.ppublica.shopify.security.service;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * A representation of a Shopify store - a "user". This object is the Principal in the OAuth2AuthenticationToken,
 * the Authentication. The api key and raw access token are saved as attributes.
 * 
 * @author N F
 *
 */
public class ShopifyStore  implements OAuth2User, Serializable {

	private static final long serialVersionUID = -912952033860273123L;

	/**
	 * The attribute key that holds the access token value.
	 */
	public static final String ACCESS_TOKEN_KEY = "shopify_access_token";

	/**
	 * The attribute key that holds the api key.
	 */
	public static final String API_KEY = "shopify_client_api_key";

	private final String name;
	private final Collection<? extends GrantedAuthority> authorities;
	private final Map<String, Object> attributes;
	
	/**
	 * Create a new ShopifyStore.
	 * 
	 * @param name The full domain name
	 * @param accessToken The raw OAuth token
	 * @param apiKey The api key of this app
	 * @param authorities The authorities granted to the app
	 */
	public ShopifyStore(String name, String accessToken, String apiKey, Collection<? extends GrantedAuthority> authorities) {			
		this.name = name;
		this.attributes = new HashMap<>();
		this.attributes.put(ACCESS_TOKEN_KEY, accessToken);
		this.attributes.put(API_KEY, apiKey);
		
		this.authorities = authorities == null ? new ArrayList<>() : authorities;
		
	}
	
	public ShopifyStore(String name, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes) {
		this.name = name;
		this.authorities = authorities != null ? authorities : new ArrayList<>();
		this.attributes =  attributes != null ? attributes : new HashMap<>();
	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}
	

}
