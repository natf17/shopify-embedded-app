package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.ppublica.shopify.security.service.ShopifyBeansUtils;

/*
 * To override, explicitly configure the OAuth2LoginConfigurer in HttpSecurity's configure().
 */
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
						.authorizationRequestResolver(getRequestResolver(http))
					.and()
		          		.redirectionEndpoint().baseUri(this.anyAuthorizationRedirectPath) // same as filterProcessesUrl
		          	.and()
		          		.tokenEndpoint().accessTokenResponseClient(getAccessTokenResponseClient(http)) // allows for seamless unit testing
		          	.and()
		          		.userInfoEndpoint().userService(getUserService(http))
		          	.and()
			          	.successHandler(getSuccessHandler(http))
			          	.loginPage(this.loginEndpoint) // for use outside of an embedded app since it involves a redirect
			          	.failureUrl(this.authenticationFailureUrl); // see AbstractAuthenticationFilterConfigurer and AbstractAuthenticationProcessingFilter	
		
	}
	
	protected AuthenticationSuccessHandler getSuccessHandler(HttpSecurityBuilder<?> http) {
		return ShopifyBeansUtils.getSuccessHandler(http);
	}
	
	protected OAuth2UserService<OAuth2UserRequest, OAuth2User> getUserService(HttpSecurityBuilder<?> http) {
		return ShopifyBeansUtils.getUserService(http);
	}

	
	protected OAuth2AuthorizationRequestResolver getRequestResolver(HttpSecurityBuilder<?> http) {
		return ShopifyBeansUtils.getRequestResolver(http);
	}
	
	protected OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> getAccessTokenResponseClient(HttpSecurityBuilder<?> http) {
		return ShopifyBeansUtils.getAccessTokenResponseClient(http);
	}
	
	

}
