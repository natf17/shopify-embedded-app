package com.ppublica.shopify.security.configurer.delegates;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.csrf.CsrfTokenRepository;


/**
 * Ensures that no CSRF token is required to uninstall the store. Since WebSecurityConfigurerAdapter applies the 
 * CsrfConfigurer by default, no configuration is necessary.
 * 
 * @author N F
 *
 */
public class ShopifyCsrf implements HttpSecurityBuilderConfigurerDelegate {
	private final Log logger = LogFactory.getLog(ShopifyCsrf.class);

	private String uninstallUri;
	private CsrfTokenRepository csrfTokenRepo;
	
	/**
	 * Construct a ShopifyCsrf.
	 * 
	 * @param uninstallUri - The path for uninstalling
	 * @param csrfTokenRepo - The CsrfTokenRepository
	 * 
	 */
	public ShopifyCsrf(String uninstallUri, CsrfTokenRepository csrfTokenRepo) {
		this.uninstallUri = uninstallUri;
		this.csrfTokenRepo = csrfTokenRepo;
	}
	
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		
		
	}

	/**
	 * Apply the custom CsrfTokenRepository and ensure the uninstall uri doesn't require a CSRF token.
	 * 
	 * @param http The HttpSecurityBuilder
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		logger.debug("Applying ShopifyCsrf init");
		
		CsrfConfigurer<HttpSecurity> configurer = new CsrfConfigurer<HttpSecurity>(null);		
		
		configurer = http.getConfigurer(configurer.getClass());
		if (configurer == null) {
			throw new RuntimeException("CsrfConfigurer is required");
		}
		
		configurer.csrfTokenRepository(csrfTokenRepo);
		configurer.ignoringAntMatchers(this.uninstallUri + "/**");
	}


}
