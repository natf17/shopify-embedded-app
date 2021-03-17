package com.ppublica.shopify.security.configurer.delegates;

import com.ppublica.shopify.security.configuration.ShopifyPaths;
import com.ppublica.shopify.security.service.DefaultShopifyUserService;
import com.ppublica.shopify.security.web.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;


/**
 * Apply all the configuration related to the OAuth2 "handshake" with Shopify, as defined in OAuth2LoginConfigurer.
 * @author N F
 *
 */
public class ShopifyOAuth2 implements HttpSecurityBuilderConfigurerDelegate {
	private final Log logger = LogFactory.getLog(ShopifyOAuth2.class);

	private String anyAuthorizationRedirectPath;
	private String loginEndpoint;
	private String authenticationFailureUrl;
	private ShopifyPaths shopifyPaths;
	private ClientRegistration shopifyClientRegistration;

	/**
	 * Construct the ShopifyOAuth2
	 *
	 * @param shopifyPaths Shopify paths
	 */
	public ShopifyOAuth2(ShopifyPaths shopifyPaths, ClientRegistration shopifyClientRegistration) {
		this.anyAuthorizationRedirectPath = shopifyPaths.getAnyAuthorizationRedirectPath();
		this.loginEndpoint = shopifyPaths.getLoginEndpoint();
		this.authenticationFailureUrl = shopifyPaths.getAuthenticationFailureUri();
		this.shopifyPaths = shopifyPaths;
		this.shopifyClientRegistration = shopifyClientRegistration;
	}

	@Override
	public void applyShopifyConfig(HttpSecurityBuilder<?> http) {
	}

	/**
	 * Configure the OAuth2LoginConfigurer. Set the custom OAuth2AuthorizationRequestResolver, the base uri
	 * on the Redirection Endpoint, a custom OAuth2AccessTokenResponseClient on the Token Endpoint, a custom
	 * OAuth2UserService on the UserInfo Endpoint, an AuthenticationSuccessHandler, the login page, and the failure
	 * uri. The objects are obtained from ShopifyBeansUtils.
	 *
	 * @param http The HttpSecurityBuilder
	 *
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void applyShopifyInit(HttpSecurityBuilder<?> http) {
		logger.debug("Applying ShopifyOAuth2 init");
		OAuth2LoginConfigurer<HttpSecurity> configurer = new OAuth2LoginConfigurer<HttpSecurity>();

		configurer = http.getConfigurer(configurer.getClass());

		if (configurer == null) {
			throw new RuntimeException("OAuth2LoginConfigurer is required");
		}
		configurer.authorizationEndpoint()
						.authorizationRequestResolver(getRequestResolver())
					.and()
		          		.redirectionEndpoint().baseUri(this.anyAuthorizationRedirectPath) // same as filterProcessesUrl
		          	.and()
		          		.tokenEndpoint().accessTokenResponseClient(getAccessTokenResponseClient()) // allows for seamless unit testing
		          	.and()
		          		.userInfoEndpoint().userService(getUserService())
		          	.and()
			          	.successHandler(getSuccessHandler())
			          	.loginPage(this.loginEndpoint) // for use outside of an embedded app since it involves a redirect
			          	.failureUrl(this.authenticationFailureUrl); // see AbstractAuthenticationFilterConfigurer and AbstractAuthenticationProcessingFilter

	}

	protected AuthenticationSuccessHandler getSuccessHandler() {
		return new NoRedirectSuccessHandler(authorizationPageStrategy(shopifyPaths));
	}

	protected OAuth2UserService<OAuth2UserRequest, OAuth2User> getUserService() {
		return new DefaultShopifyUserService();
	}

	protected OAuth2AuthorizationRequestResolver getRequestResolver() {
		return new ShopifyOAuth2AuthorizationRequestResolver(
				clientRegistrationRepository(shopifyClientRegistration),
				customAuthorizationRequestRepository(shopifyPaths),
				shopifyPaths.getInstallPath(),
				shopifyPaths.getLoginEndpoint()
		);
	}

	protected OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> getAccessTokenResponseClient() {
		return new ShopifyAuthorizationCodeTokenResponseClient();
	}

	private AuthorizationSuccessPageStrategy authorizationPageStrategy(ShopifyPaths path) {
		boolean isCustomAuthorizationRedirectPath = path.isCustomAuthorizationRedirectPath();

		if(isCustomAuthorizationRedirectPath) {
			return new ForwardAuthorizationSuccessPageStrategy(path.getAuthorizationRedirectPath());
		} else {
			return new GenerateDefaultAuthorizationPageStrategy(path.getMenuLinks());
		}
	}

	private ClientRegistrationRepository clientRegistrationRepository(ClientRegistration shopifyClientRegistration) {
		return new InMemoryClientRegistrationRepository(shopifyClientRegistration);
	}

	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository(ShopifyPaths shopifyPaths) {
		return new ShopifyHttpSessionOAuth2AuthorizationRequestRepository(shopifyPaths.getInstallPath());
	}

}
