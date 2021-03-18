package com.ppublica.shopify.security.service;

import java.util.Map;

import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.repository.TokenRepository;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.ShopifyPaths;
import com.ppublica.shopify.security.configurer.delegates.HttpSecurityBuilderConfigurerDelegate;
import com.ppublica.shopify.security.web.NoRedirectSuccessHandler;
import com.ppublica.shopify.security.web.ShopifyAuthorizationCodeTokenResponseClient;
import com.ppublica.shopify.security.web.ShopifyOAuth2AuthorizationRequestResolver;

/**
 * A facade for extracting beans from the HttpSecurityBuilder's ApplicationContext. The following beans are
 * expected to exist:
 * <ul>
 * 	<li>ShopifyOAuth2AuthorizationRequestResolver</li>
 * 	<li>ShopifyAuthorizationCodeTokenResponseClient</li>
 * 	<li>DefaultShopifyUserService</li>
 * 	<li>NoRedirectSuccessHandler</li>
 * 	<li>ShopifyVerificationStrategy</li>
 * 	<li>ShopifyOAuth2AuthorizedClientService</li>
 * 	<li>MappingJackson2HttpMessageConverter</li>
 * 	<li>ShopifyPaths</li>
 * 	<li>Multiple HttpSecurityBuilderConfigurerDelegate</li>
 * </ul>
 * @author N F
 * @see com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer
 */
public class ShopifyBeansUtils {

	public static OAuth2AuthorizationRequestResolver getRequestResolver(HttpSecurityBuilder<?> http) {
		ShopifyOAuth2AuthorizationRequestResolver resolver = http.getSharedObject(ApplicationContext.class).getBean(ShopifyOAuth2AuthorizationRequestResolver.class);

		if(resolver == null) {
			throw new RuntimeException("No ShopifyOAuth2AuthorizationRequestResolver bean found");
		}

		return resolver;
	}

	public static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> getAccessTokenResponseClient(HttpSecurityBuilder<?> http) {
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> client = http.getSharedObject(ApplicationContext.class).getBean(ShopifyAuthorizationCodeTokenResponseClient.class);

		if(client == null) {
			throw new RuntimeException("No ShopifyAuthorizationCodeTokenResponseClient bean found");
		}

		return client;
	}

	public static OAuth2UserService<OAuth2UserRequest, OAuth2User> getUserService(HttpSecurityBuilder<?> http) {
		DefaultShopifyUserService userService = http.getSharedObject(ApplicationContext.class).getBean(DefaultShopifyUserService.class);

		if(userService == null) {
			throw new RuntimeException("No DefaultShopifyUserService bean found");
		}

		return userService;
	}

	public static AuthenticationSuccessHandler getSuccessHandler(HttpSecurityBuilder<?> http) {
		AuthenticationSuccessHandler successHandler = http.getSharedObject(ApplicationContext.class).getBean(NoRedirectSuccessHandler.class);

		if(successHandler == null) {
			throw new RuntimeException("No NoRedirectSuccessHandler bean found");
		}

		return successHandler;
	}

	public static ShopifyVerificationStrategy getShopifyVerificationStrategy(HttpSecurityBuilder<?> http) {
		ShopifyVerificationStrategy verificationStrategy = http.getSharedObject(ApplicationContext.class).getBean(ShopifyVerificationStrategy.class);

		if(verificationStrategy == null) {
			throw new RuntimeException("No ShopifyVerificationStrategy bean found");
		}

		return verificationStrategy;
	}

	public static OAuth2AuthorizedClientService getAuthorizedClientService(HttpSecurityBuilder<?> http) {
		OAuth2AuthorizedClientService authorizedClientService = http.getSharedObject(ApplicationContext.class).getBean(ShopifyOAuth2AuthorizedClientService.class);

		if(authorizedClientService == null) {
			throw new RuntimeException("No ShopifyOAuth2AuthorizedClientService bean found");
		}

		return authorizedClientService;
	}

	public static MappingJackson2HttpMessageConverter getJacksonConverter(HttpSecurityBuilder<?> http) {
		MappingJackson2HttpMessageConverter jacksonConverter = http.getSharedObject(ApplicationContext.class).getBean(MappingJackson2HttpMessageConverter.class);

		if(jacksonConverter == null) {
			throw new RuntimeException("No MappingJackson2HttpMessageConverter bean found");
		}

		return jacksonConverter;
	}

	public static ShopifyPaths getShopifyPaths(HttpSecurityBuilder<?> http) {
		ShopifyPaths shopifyPaths = http.getSharedObject(ApplicationContext.class).getBean(ShopifyPaths.class);

		if(shopifyPaths == null) {
			throw new RuntimeException("No ShopifyPaths bean found");
		}

		return shopifyPaths;
	}

	public static Map<String, HttpSecurityBuilderConfigurerDelegate> getBuilderDelegates(HttpSecurityBuilder<?> http) {
		Map<String, HttpSecurityBuilderConfigurerDelegate> delegates = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				http.getSharedObject(ApplicationContext.class), HttpSecurityBuilderConfigurerDelegate.class);

		return delegates;
	}

	public static ClientRegistration getClientRegistration(HttpSecurityBuilder<?> http) {
		ClientRegistration clientRegistration = http.getSharedObject(ApplicationContext.class).getBean(ClientRegistration.class);

		if(clientRegistration == null) {
			throw new RuntimeException("No ClientRegistration bean found");
		}

		return clientRegistration;
	}

	public static TokenRepository getTokenRepository(HttpSecurityBuilder<?> http) {
		TokenRepository tokenRepository = http.getSharedObject(ApplicationContext.class).getBean(TokenRepository.class);

		if(tokenRepository == null) {
			throw new RuntimeException("No TokenRepository bean found");
		}

		return tokenRepository;
	}

	public static CipherPassword getCipherPassword(HttpSecurityBuilder<?> http) {
		CipherPassword password = http.getSharedObject(ApplicationContext.class).getBean(CipherPassword.class);

		if(password == null) {
			throw new RuntimeException("No CipherPassword bean found");
		}

		return password;
	}
}
