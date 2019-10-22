package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;

/*
 * Sets the "logout" and "logoutSuccessUrl" values.
 * 
 * Since WebSecurityConfigurerAdapter applies the LogoutConfigurer by default, 
 * no configuration is necessary.
 */
public class ShopifyLogout implements HttpSecurityBuilderConfigurerDelegate {
	
	private String loginEndpoint;
	private String logoutEndpoint;
	
	public ShopifyLogout(String loginEndpoint, String logoutEndpoint) {
		this.loginEndpoint = loginEndpoint;
		this.logoutEndpoint = logoutEndpoint;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		LogoutConfigurer<HttpSecurity> configurer = new LogoutConfigurer<HttpSecurity>();		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("LogoutConfigurer is required");
		}
		
		configurer.logoutUrl(this.loginEndpoint)
      			  .logoutSuccessUrl(this.logoutEndpoint);
	}

	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		
	}


}
