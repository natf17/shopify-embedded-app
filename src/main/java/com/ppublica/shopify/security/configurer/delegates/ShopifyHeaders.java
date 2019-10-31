package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;

/*
 * Ensures the app can be served as an embedded app by preventing Spring from writing the X-Frame-Options header.
 * 
 * Since WebSecurityConfigurerAdapter applies the HeadersConfigurer by default, 
 * no configuration is necessary.
 */
public class ShopifyHeaders implements HttpSecurityBuilderConfigurerDelegate {

	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		
		
	}
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		HeadersConfigurer<?> configurer = new HeadersConfigurer<>();		
		//Class<? extends SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity>> clazz = (Class<? extends SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity>>) configurer.getClass();		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("HeadersConfigurer is required");
		}
		System.out.println("Calling disable");
		configurer.frameOptions().disable();
	}

}
