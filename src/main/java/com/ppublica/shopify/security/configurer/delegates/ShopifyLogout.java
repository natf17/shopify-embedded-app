package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;

import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;

/*
 * Sets the "logout" and "logoutSuccessUrl" values.
 * 
 * Since WebSecurityConfigurerAdapter applies the LogoutConfigurer by default, 
 * no configuration is necessary.
 */
public class ShopifyLogout implements HttpSecurityBuilderConfigurerDelegate {
	
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		LogoutConfigurer<HttpSecurity> configurer = new LogoutConfigurer<HttpSecurity>();		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("LogoutConfigurer is required");
		}
		
		configurer.logoutUrl(ShopifySecurityConfigurer.LOGOUT_ENDPOINT)
      			  .logoutSuccessUrl(ShopifySecurityConfigurer.LOGIN_ENDPOINT);
	}

	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		
	}


}
