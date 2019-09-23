package com.ppublica.shopify.security.configurer;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configurer.delegates.HttpSecurityBuilderConfigurerDelegate;
import com.ppublica.shopify.security.configurer.delegates.ShopifyAuthorization;
import com.ppublica.shopify.security.configurer.delegates.ShopifyChannelSecurity;
import com.ppublica.shopify.security.configurer.delegates.ShopifyCsrf;
import com.ppublica.shopify.security.configurer.delegates.ShopifyHeaders;
import com.ppublica.shopify.security.configurer.delegates.ShopifyLogout;
import com.ppublica.shopify.security.configurer.delegates.ShopifyOAuth2;
import com.ppublica.shopify.security.filters.ShopifyExistingTokenFilter;
import com.ppublica.shopify.security.filters.ShopifyOriginFilter;
import com.ppublica.shopify.security.filters.UninstallFilter;
import com.ppublica.shopify.security.service.ShopifyBeansUtils;


public class ShopifySecurityConfigurer<H extends HttpSecurityBuilder<H>>
	extends AbstractHttpConfigurer<ShopifySecurityConfigurer<H>, H> {
	
	public static final String INSTALL_PATH = "/install";
	public static final String ANY_INSTALL_PATH = INSTALL_PATH + "/**";
	public static final String AUTHORIZATION_REDIRECT_PATH = "/login/app/oauth2/code";
	public static final String ANY_AUTHORIZATION_REDIRECT_PATH = AUTHORIZATION_REDIRECT_PATH + "/**";
	public static final String LOGIN_ENDPOINT = "/init";
	public static final String LOGOUT_ENDPOINT = "/logout";
	public static final String AUTHENTICATION_FALURE_URL = "/auth/error";
	public static final String UNINSTALL_URI = "/store/uninstall";
	
	private final List<HttpSecurityBuilderConfigurerDelegate> shopifyConfigurers;

	public ShopifySecurityConfigurer() {
		shopifyConfigurers = new ArrayList<>();
		
		shopifyConfigurers.add(new ShopifyHeaders());
		shopifyConfigurers.add(new ShopifyChannelSecurity());
		shopifyConfigurers.add(new ShopifyCsrf());
		shopifyConfigurers.add(new ShopifyAuthorization());
		shopifyConfigurers.add(new ShopifyLogout());
		shopifyConfigurers.add(new ShopifyOAuth2());

	}
	
	// this configurer's init() method is applied before all others
	@Override
	public void init(H http) {
		for(HttpSecurityBuilderConfigurerDelegate del : shopifyConfigurers) {
			del.applyShopifyConfig(http);
		}
		
	}

	
	@Override
	public void configure(H http) {
		ShopifyVerificationStrategy verStr = ShopifyBeansUtils.getShopifyVerificationStrategy(http);
		OAuth2AuthorizedClientService cS = ShopifyBeansUtils.getAuthorizedClientService(http);
		
		http.addFilterAfter(new ShopifyOriginFilter(verStr, ANY_AUTHORIZATION_REDIRECT_PATH, ANY_INSTALL_PATH), LogoutFilter.class);
		http.addFilterAfter(new ShopifyExistingTokenFilter(cS, INSTALL_PATH), ShopifyOriginFilter.class);
		http.addFilterBefore(new UninstallFilter(UNINSTALL_URI, verStr, cS, ShopifyBeansUtils.getJacksonConverter(http)), OAuth2AuthorizationRequestRedirectFilter.class);
		
		
	}

}
