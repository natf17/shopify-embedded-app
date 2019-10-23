package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;

import com.ppublica.shopify.security.service.ShopifyBeansUtils;

public class ShopifyOAuth2 implements HttpSecurityBuilderConfigurerDelegate {
	
	private String anyAuthorizationRedirectPath;
	private String loginEndpoint;
	private String authenticationFailureUrl;
	
	public ShopifyOAuth2(String anyAuthorizationRedirectPath, String loginEndpoint, String authenticationFailureUrl) {
		this.anyAuthorizationRedirectPath = anyAuthorizationRedirectPath;
		this.loginEndpoint = loginEndpoint;
		this.authenticationFailureUrl = authenticationFailureUrl;
	}
	
	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
		
	}

	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		OAuth2LoginConfigurer<HttpSecurity> configurer = new OAuth2LoginConfigurer<HttpSecurity>();		
		
		configurer = http.getConfigurer(configurer.getClass());
		
		if (configurer == null) {
			throw new RuntimeException("OAuth2LoginConfigurer is required");
		}
		configurer.authorizationEndpoint()
						.authorizationRequestResolver(ShopifyBeansUtils.getRequestResolver(http))
					.and()
		          		.redirectionEndpoint().baseUri(this.anyAuthorizationRedirectPath) // same as filterProcessesUrl
		          	.and()
		          		.tokenEndpoint().accessTokenResponseClient(ShopifyBeansUtils.getAccessTokenResponseClient(http)) // allows for seamless unit testing
		          	.and()
		          		.userInfoEndpoint().userService(ShopifyBeansUtils.getUserService(http))
		          	.and()
			          	.successHandler(ShopifyBeansUtils.getSuccessHandler(http))
			          	.loginPage(this.loginEndpoint) // for use outside of an embedded app since it involves a redirect
			          	.failureUrl(this.authenticationFailureUrl); // see AbstractAuthenticationFilterConfigurer and AbstractAuthenticationProcessingFilter	
		
		
	}
	



}
