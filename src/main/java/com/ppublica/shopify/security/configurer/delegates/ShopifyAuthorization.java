package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;

public class ShopifyAuthorization implements HttpSecurityBuilderConfigurerDelegate {

	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		ExpressionUrlAuthorizationConfigurer<HttpSecurity> configurer = new ExpressionUrlAuthorizationConfigurer<HttpSecurity>(null);		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("ExpressionUrlAuthorizationConfigurer is required");
		}
		
		configurer.getRegistry()
					.mvcMatchers(ShopifySecurityConfigurer.LOGIN_ENDPOINT).permitAll()
					.mvcMatchers(ShopifySecurityConfigurer.ANY_INSTALL_PATH).permitAll()
					.mvcMatchers("/favicon.ico").permitAll()
					.anyRequest().authenticated();
		}

}