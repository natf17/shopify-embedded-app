package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer;

public class ShopifyChannelSecurity implements HttpSecurityBuilderConfigurerDelegate {

	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		ChannelSecurityConfigurer<HttpSecurity> configurer = new ChannelSecurityConfigurer<HttpSecurity>(null);		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("ChannelSecurityConfigurer is required");
		}
		
		configurer.getRegistry()
						.anyRequest()
							.requiresSecure();
	}

}
