package com.ppublica.shopify.security.configurer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.ShopifyPaths;
import com.ppublica.shopify.security.configurer.delegates.HttpSecurityBuilderConfigurerDelegate;
import com.ppublica.shopify.security.filters.ShopifyExistingTokenFilter;
import com.ppublica.shopify.security.filters.ShopifyOriginFilter;
import com.ppublica.shopify.security.filters.UninstallFilter;
import com.ppublica.shopify.security.service.ShopifyBeansUtils;

/*
 * By default, the WebSecurityConfigurerAdapter will look in spring.factories for AbstractHttpConfigurers to apply, where
 * it should find ShopifySecurityConfigurer. This configurer will be applied before all others (ex. configurers applied in 
 * the overridden configure(Http) method), and therefore its init() and configure() methods will be invoked before those of
 * other configurers.
 * 
 * init():
 * - Find HttpSecurityBuilderConfigurerDelegate beans
 * - Allow each to initialize HttpSecurityBuilder
 * 
 * configure():
 * - Allow each HttpSecurityBuilderConfigurerDelegate to configure HttpSecurityBuilder
 * - Add the following filters, each configured based on beans retrieved from the context:
 * 		- ShopifyOriginFilter
 * 		- ShopifyExistingTokenFilter
 * 		- UninstallFilter
 * 		- DefaultInstallFilter
 * 		- DefaultAuthorizationRedirectPathFilter
 * 
 */
public class ShopifySecurityConfigurer<H extends HttpSecurityBuilder<H>>
	extends AbstractHttpConfigurer<ShopifySecurityConfigurer<H>, H> {

	private final List<HttpSecurityBuilderConfigurerDelegate> shopifyConfigurers = new ArrayList<>();

	
	@Override
	public void init(H http) {
		Map<String, HttpSecurityBuilderConfigurerDelegate> dels = ShopifyBeansUtils.getBuilderDelegates(http);
		
		shopifyConfigurers.addAll(dels.values());
		
		for(HttpSecurityBuilderConfigurerDelegate del : shopifyConfigurers) {
			del.applyShopifyInit(http);
		}
		
	}

	
	@Override
	public void configure(H http) {
		
		for(HttpSecurityBuilderConfigurerDelegate del : shopifyConfigurers) {
			del.applyShopifyConfig(http);
		}
			
		ShopifyVerificationStrategy verStr = ShopifyBeansUtils.getShopifyVerificationStrategy(http);
		OAuth2AuthorizedClientService cS = ShopifyBeansUtils.getAuthorizedClientService(http);
		ShopifyPaths sP = ShopifyBeansUtils.getShopifyPaths(http);
		
		http.addFilterAfter(new ShopifyOriginFilter(verStr, sP.getAnyAuthorizationRedirectPath(), sP.getAnyInstallPath()), LogoutFilter.class);
		http.addFilterAfter(new ShopifyExistingTokenFilter(cS, sP.getInstallPath()), ShopifyOriginFilter.class);
		http.addFilterBefore(new UninstallFilter(sP.getUninstallUri(), verStr, cS, ShopifyBeansUtils.getJacksonConverter(http)), OAuth2AuthorizationRequestRedirectFilter.class);
		
		
	}

}
