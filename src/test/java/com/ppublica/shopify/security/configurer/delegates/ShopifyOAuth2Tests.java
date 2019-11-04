package com.ppublica.shopify.security.configurer.delegates;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.ppublica.shopify.security.service.ShopifyBeansUtils;

public class ShopifyOAuth2Tests {
	
	
	// OAuth2AuthorizationRequestResolver - no need for bean
	/*
	 * If not explicitly set, OAuth2LoginConfigurer uses authorizationRequestBaseUri, or default uri to build a default
	 */
	
	// default is triggerred
	// if one is provided by user, it will be used (!warning)
	
	
	
	
	
	// OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> : default
	/*
	 * If not explicitly set, OAuth2LoginCOnfigurer uses creates a default
	 */
	
	// default is triggerred
	// if one is provided by user, it will be used (!warning)
	
	
	// AuthenticationSuccessHandler
	// must be explicitly set
	// default is triggerred
	// if one is provided by user, it will be used (!warning)
	
	
	// OAuth2UserService<OAuth2UserRequest, OAuth2User>
	// if not explicitly set, searches for bean

	
}
