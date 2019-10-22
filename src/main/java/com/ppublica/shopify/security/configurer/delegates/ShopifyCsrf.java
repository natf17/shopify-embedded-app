package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;

/*
 * Ensures that no CSRF token is required to uninstall the store.
 * 
 * Since WebSecurityConfigurerAdapter applies the CsrfConfigurer by default, 
 * no configuration is necessary.
 */
public class ShopifyCsrf implements HttpSecurityBuilderConfigurerDelegate {
	
	private String uninstallUri;
	
	public ShopifyCsrf(String uninstallUri) {
		this.uninstallUri = uninstallUri;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		CsrfConfigurer<HttpSecurity> configurer = new CsrfConfigurer<HttpSecurity>(null);		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("CsrfConfigurer is required");
		}
		
		configurer.ignoringAntMatchers(this.uninstallUri + "/*");
		
	}

	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		
	}


}
