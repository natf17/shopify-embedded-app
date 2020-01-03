package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

/**
 * Interface to apply custom Shopify configuration to already-existing HttpSecurity configurers.
 * 
 * @author N F
 *
 */
public interface HttpSecurityBuilderConfigurerDelegate {
	/**
	 * Initialize the configurer. Only shared state should be created and modified.
	 * 
	 * @param http The HttpSecurityBuilder
	 */
	void applyShopifyInit(HttpSecurityBuilder<?> http);
	
	/**
	 * Configure the configurer. You can set the necessary properties.
	 * 
	 * @param http The HttpSecurityBuilder
	 */
	void applyShopifyConfig(HttpSecurityBuilder<?> http);
}
