package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

public interface HttpSecurityBuilderConfigurerDelegate {
	void applyShopifyConfig(HttpSecurityBuilder<?> http);
}
