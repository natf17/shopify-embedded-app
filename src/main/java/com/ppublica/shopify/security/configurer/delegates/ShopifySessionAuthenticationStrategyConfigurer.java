package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.ppublica.shopify.security.web.SaveAuthenticationSessionAuthenticationStrategy;

/*
 * AbstractAuthenticationFilterConfigurer looks for a SessionAuthenticationStrategy in HttpSecurity's
 * shared objects, and sets it on OAuth2LoginAuthenticationFilter.
 * 
 *  This configurer adds SaveAuthenticationSessionAuthenticationStrategy to HttpSecurity's map of shared
 *  objects.
 */
public class ShopifySessionAuthenticationStrategyConfigurer implements HttpSecurityBuilderConfigurerDelegate {

	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		http.setSharedObject(SessionAuthenticationStrategy.class, new SaveAuthenticationSessionAuthenticationStrategy());
		
	}

	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) { }

}
