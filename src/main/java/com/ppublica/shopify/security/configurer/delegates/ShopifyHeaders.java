package com.ppublica.shopify.security.configurer.delegates;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;


/**
 * Ensures the app can be served as an embedded app by preventing Spring from writing the X-Frame-Options header.
 * Since WebSecurityConfigurerAdapter applies the HeadersConfigurer by default, no configuration is necessary.
 * 
 * @author N F
 *
 */
public class ShopifyHeaders implements HttpSecurityBuilderConfigurerDelegate {
	private final Log logger = LogFactory.getLog(ShopifyHeaders.class);

	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		
		
	}
	
	/**
	 * Disable the XFrameOptionsHeaderWriter, which prevents the X-Frame-Options header from being added.
	 * 
	 * @param http The HttpSecurityBuilder
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		logger.debug("Applying ShopifyHeaders init");
		HeadersConfigurer<?> configurer = new HeadersConfigurer<>();				
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("HeadersConfigurer is required");
		}
		configurer.frameOptions().disable();
	}

}
