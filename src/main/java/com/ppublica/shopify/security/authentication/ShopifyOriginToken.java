package com.ppublica.shopify.security.authentication;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


/**
 * The presence of this token indicates that the request came from Shopify. It's a short-lived Authentication 
 * object; it never exists past ShopifyExistingTokenFilter. 
 * 
 * @author N F
 * @see com.ppublica.shopify.security.filters.ShopifyExistingTokenFilter
 */
public class ShopifyOriginToken implements Authentication {

	private static final long serialVersionUID = 6956977021883422793L;
	

	@Override
	public String getName() {
		return "shopifyOriginToken";
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return null;
	}

	/**
	 * @return false
	 */
	@Override
	public boolean isAuthenticated() {
		return false;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		
	}

}
