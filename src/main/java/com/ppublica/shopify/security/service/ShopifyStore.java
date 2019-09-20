package com.ppublica.shopify.security.service;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

// stores the Access Token as an attribute

public class ShopifyStore  implements OAuth2User, Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -912952033860273123L;

	public static final String ACCESS_TOKEN_KEY = "shopify_access_token";
	public static final String API_KEY = "shopify_client_api_key";

	private final String name;
	private final Collection<? extends GrantedAuthority> authorities;
	private final Map<String, Object> attributes;
	
	public ShopifyStore(String name, String accessToken, String apiKey) {			
		this.name = name;
		this.attributes = new HashMap<>();
		this.attributes.put(ACCESS_TOKEN_KEY, accessToken);
		this.attributes.put(API_KEY, apiKey);
		
		this.authorities = new ArrayList<>();

		
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
