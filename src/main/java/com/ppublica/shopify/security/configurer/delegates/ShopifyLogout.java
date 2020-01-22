package com.ppublica.shopify.security.configurer.delegates;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;


/**
 * Sets the "logout" and "logoutSuccessUrl" values. Since WebSecurityConfigurerAdapter applies the LogoutConfigurer 
 * by default, no configuration is necessary.
 * 
 * @author N F
 *
 */
public class ShopifyLogout implements HttpSecurityBuilderConfigurerDelegate {
	private final Log logger = LogFactory.getLog(ShopifyLogout.class);

	private String loginEndpoint;
	private String logoutEndpoint;
	
	/**
	 * Build ShopifyLogout.
	 *  
	 * @param loginEndpoint The login uri
	 * @param logoutEndpoint The logout uri
	 */
	public ShopifyLogout(String loginEndpoint, String logoutEndpoint) {
		this.loginEndpoint = loginEndpoint;
		this.logoutEndpoint = logoutEndpoint;
	}
	
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) { }

	/**
	 * Set the login and logout uris of LogoutConfigurer.
	 * 
	 * @param http The HttpSecurityBuilder
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		logger.debug("Applying ShopifyLogout init");
		System.out.println("shouldve just logged");
		LogoutConfigurer<HttpSecurity> configurer = new LogoutConfigurer<HttpSecurity>();		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("LogoutConfigurer is required");
		}
		
		configurer.logoutUrl(this.logoutEndpoint)
      			  .logoutSuccessUrl(this.loginEndpoint);
		
	}


}
