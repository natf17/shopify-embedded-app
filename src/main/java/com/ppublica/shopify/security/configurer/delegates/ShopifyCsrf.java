package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.csrf.CsrfTokenRepository;

/*
 * Ensures that no CSRF token is required to uninstall the store.
 * 
 * Since WebSecurityConfigurerAdapter applies the CsrfConfigurer by default, 
 * no configuration is necessary.
 */
public class ShopifyCsrf implements HttpSecurityBuilderConfigurerDelegate {
	
	private String uninstallUri;
	private CsrfTokenRepository csrfTokenRepo;
	
	public ShopifyCsrf(String uninstallUri, CsrfTokenRepository csrfTokenRepo) {
		this.uninstallUri = uninstallUri;
		this.csrfTokenRepo = csrfTokenRepo;
	}
	
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		
		
	}

	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		CsrfConfigurer<HttpSecurity> configurer = new CsrfConfigurer<HttpSecurity>(null);		
		
		configurer = http.getConfigurer(configurer.getClass());
		if (configurer == null) {
			throw new RuntimeException("CsrfConfigurer is required");
		}
		
		configurer.csrfTokenRepository(csrfTokenRepo);
		configurer.ignoringAntMatchers(this.uninstallUri + "/**");
	}


}
