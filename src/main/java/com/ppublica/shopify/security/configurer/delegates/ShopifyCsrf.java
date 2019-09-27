package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;

import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;

/*
 * Ensures that no CSRF token is required to uninstall the store.
 * 
 * Since WebSecurityConfigurerAdapter applies the CsrfConfigurer by default, 
 * no configuration is necessary.
 */
public class ShopifyCsrf implements HttpSecurityBuilderConfigurerDelegate {
	
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		CsrfConfigurer<HttpSecurity> configurer = new CsrfConfigurer<HttpSecurity>(null);		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("CsrfConfigurer is required");
		}
		
		configurer.ignoringAntMatchers(ShopifySecurityConfigurer.UNINSTALL_URI + "/*");
		
	}

	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		
	}


}