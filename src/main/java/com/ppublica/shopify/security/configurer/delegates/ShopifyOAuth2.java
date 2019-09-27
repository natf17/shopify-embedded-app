package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;

import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;
import com.ppublica.shopify.security.service.ShopifyBeansUtils;

public class ShopifyOAuth2 implements HttpSecurityBuilderConfigurerDelegate {
	
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
		          		.redirectionEndpoint().baseUri(ShopifySecurityConfigurer.ANY_AUTHORIZATION_REDIRECT_PATH) // same as filterProcessesUrl
		          	.and()
		          		.tokenEndpoint().accessTokenResponseClient(ShopifyBeansUtils.getAccessTokenResponseClient(http)) // allows for seamless unit testing
		          	.and()
		          		.userInfoEndpoint().userService(ShopifyBeansUtils.getUserService(http))
		          	.and()
			          	.successHandler(ShopifyBeansUtils.getSuccessHandler(http))
			          	.loginPage(ShopifySecurityConfigurer.LOGIN_ENDPOINT) // for use outside of an embedded app since it involves a redirect
			          	.failureUrl(ShopifySecurityConfigurer.AUTHENTICATION_FALURE_URL); // see AbstractAuthenticationProcessingFilter	
		
		
	}
	



}
