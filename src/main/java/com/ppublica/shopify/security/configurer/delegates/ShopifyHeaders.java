package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;

public class ShopifyHeaders implements HttpSecurityBuilderConfigurerDelegate {

	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		HeadersConfigurer<?> configurer = new HeadersConfigurer<>();		
		//Class<? extends SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity>> clazz = (Class<? extends SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity>>) configurer.getClass();		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("HeadersConfigurer is required");
		}
		
		configurer.frameOptions().disable();
		
	}

}
