package com.ppublica.shopify.security.configurer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.repository.TokenRepository;
import com.ppublica.shopify.security.service.ShopifyOAuth2AuthorizedClientService;
import com.ppublica.shopify.security.service.TokenService;
import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;

import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configuration.ShopifyPaths;
import com.ppublica.shopify.security.configurer.delegates.HttpSecurityBuilderConfigurerDelegate;
import com.ppublica.shopify.security.filters.DefaultAuthenticationFailureFilter;
import com.ppublica.shopify.security.filters.DefaultInstallFilter;
import com.ppublica.shopify.security.filters.DefaultLoginEndpointFilter;
import com.ppublica.shopify.security.filters.DefaultUserInfoFilter;
import com.ppublica.shopify.security.filters.ShopifyExistingTokenFilter;
import com.ppublica.shopify.security.filters.ShopifyOriginFilter;
import com.ppublica.shopify.security.filters.UninstallFilter;
import com.ppublica.shopify.security.service.ShopifyBeansUtils;


/**
 * The main configurer that WebSecurityConfigurerAdapter finds and applies to HttoSecurity to connfigure it for
 * OAuth2 authorization with Shopify.
 *
 * <p>By default, the WebSecurityConfigurerAdapter will look in spring.factories for AbstractHttpConfigurers to apply, where
 * it should find ShopifySecurityConfigurer. This configurer's init() and configure() methods will be invoked in the
 * following order:</p>
 *
 * <ol>
 * <li>configurers WebSecurityConfigurerAdapter adds by default</li>
 * <li>ShopifySecurityConfigurer</li>
 * <li>configurers added in overridden configure(HttpSecurity) method</li>
 * </ol>
 *
 *
 * @author N F
 * @see com.ppublica.shopify.security.service.ShopifyBeansUtils
 *
 */
public class ShopifySecurityConfigurer<H extends HttpSecurityBuilder<H>>
	extends AbstractHttpConfigurer<ShopifySecurityConfigurer<H>, H> {
	private final Log logger = LogFactory.getLog(ShopifySecurityConfigurer.class);

	private final List<HttpSecurityBuilderConfigurerDelegate> shopifyConfigurers = new ArrayList<>();

	/**
	 * Get all HttpSecurityBuilderConfigurerDelegate from ShopifyBeansUtils.
	 *
	 * @param http The HttpSecurity
	 * @return a Map of HttpSecurityBuilderConfigurerDelegates
	 */
	protected Map<String, HttpSecurityBuilderConfigurerDelegate> getBuilderDelegates(H http) {
		return ShopifyBeansUtils.getBuilderDelegates(http);
	}

	/**
	 * Obtain all HttpSecurityBuilderConfigurerDelegate beans and allow each to initialize HttpSecurityBuilder
	 *
	 * @param http The HttpSecurity
	 */
	@Override
	public void init(H http) {
		Map<String, HttpSecurityBuilderConfigurerDelegate> dels = getBuilderDelegates(http);

		shopifyConfigurers.addAll(dels.values());

		if(logger.isDebugEnabled()) {
			logger.info("***ShopifySecurityConfigurer init: " + dels.size() + "configurers found");
		}

		for(HttpSecurityBuilderConfigurerDelegate del : shopifyConfigurers) {
			del.applyShopifyInit(http);
		}

	}

	/**
	 * Allow each HttpSecurityBuilderConfigurerDelegate to configure HttpSecurityBuilder/HttpSecurity.
	 * Add the following filters, each configured based on beans retrieved from the context:
	 * <ul>
	 * 	<li>ShopifyOriginFilter</li>
	 * 	<li>ShopifyExistingTokenFilter</li>
	 * 	<li>UninstallFilter</li>
	 *
	 *	<li>DefaultInstallFilter</li>
	 *	<li>DefaultLoginEndpointFilter</li>
	 * 	<li>DefaultAuthenticationFailureFilter</li>
	 * 	<li>DefaultUserInfoFilter</li>
	 * </ul>
	 *
	 * @param http The HttpSecurity
	 */
	@Override
	public void configure(H http) {

		for(HttpSecurityBuilderConfigurerDelegate del : shopifyConfigurers) {
			del.applyShopifyConfig(http);
		}

		ClientRegistration clientRegistration = ShopifyBeansUtils.getClientRegistration(http);
		ClientRegistrationRepository clientRegistrationRepository = clientRegistrationRepository(clientRegistration);
		ShopifyPaths sP = ShopifyBeansUtils.getShopifyPaths(http);
		ShopifyHttpSessionOAuth2AuthorizationRequestRepository sessionRepository = customAuthorizationRequestRepository(sP);
		TokenRepository tokenRepository = ShopifyBeansUtils.getTokenRepository(http);
		CipherPassword cipherPassword = ShopifyBeansUtils.getCipherPassword(http);
		TokenService tokenService = tokenService(tokenRepository, cipherPassword, clientRegistrationRepository);

		ShopifyVerificationStrategy verStr = shopifyVerficationStrategy(clientRegistrationRepository, sessionRepository);
		OAuth2AuthorizedClientService cS = clientService(tokenService);

		http.addFilterAfter(new ShopifyOriginFilter(verStr, sP.getAnyAuthorizationRedirectPath(), sP.getAnyInstallPath()), LogoutFilter.class);
		http.addFilterAfter(new ShopifyExistingTokenFilter(cS, sP.getInstallPath()), ShopifyOriginFilter.class);
		http.addFilterBefore(new UninstallFilter(sP.getUninstallUri(), verStr, cS, ShopifyBeansUtils.getJacksonConverter(http)), OAuth2AuthorizationRequestRedirectFilter.class);

		logger.info("***ShopifySecurityConfigurer configure... filters added:");
		logger.info("ShopifyOriginFilter");
		logger.info("ShopifyExistingTokenFilter");
		logger.info("UninstallFilter");

		Map<String, String> menuLinks = new HashMap<>();
		boolean isCustomInstallPath = sP.isCustomInstallPath();
		boolean isCustomLoginEndpoint = sP.isCustomLoginEndpoint();
		boolean isCustomAuthenticationFailurePage = sP.isCustomAuthenticationFailureUri();
		boolean isUserInfoPageEnabled = sP.isUserInfoPageEnabled();


		//DefaultInstallFilter
		if(!isCustomInstallPath) {
			// bypass security...
			http.addFilterBefore(new DefaultInstallFilter(sP.getInstallPath(), menuLinks), FilterSecurityInterceptor.class);
			logger.info("DefaultInstallFilter");

		}

		//DefaultLoginEndpointFilter
		if(!isCustomLoginEndpoint) {
			// since it doesn't modify the Authentication...
			http.addFilterAfter(new DefaultLoginEndpointFilter(sP.getLoginEndpoint(), sP.getInstallPath(), sP.getLogoutEndpoint()), ConcurrentSessionFilter.class);
			logger.info("DefaultLoginEndpointFilter");
		}

		//DefaultAuthenticationFailureFilter
		if(!isCustomAuthenticationFailurePage) {
			http.addFilterAfter(new DefaultAuthenticationFailureFilter(sP.getAuthenticationFailureUri()), DefaultLogoutPageGeneratingFilter.class);
			logger.info("DefaultAuthenticationFailureFilter");
		}

		//DefaultUserInfoFilter
		if(isUserInfoPageEnabled) {
			// implements own "security"
			http.addFilterBefore(new DefaultUserInfoFilter(sP.getUserInfoPagePath()), FilterSecurityInterceptor.class);
			logger.info("DefaultUserInfoFilter");
		}

	}

	private ClientRegistrationRepository clientRegistrationRepository(ClientRegistration shopifyClientRegistration) {
		return new InMemoryClientRegistrationRepository(shopifyClientRegistration);
	}

	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository(ShopifyPaths shopifyPaths) {
		return new ShopifyHttpSessionOAuth2AuthorizationRequestRepository(shopifyPaths.getInstallPath());
	}

	private ShopifyVerificationStrategy shopifyVerficationStrategy(
			ClientRegistrationRepository clientRegistrationRepository,
			ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository
	) {
		return new ShopifyVerificationStrategy(clientRegistrationRepository, customAuthorizationRequestRepository);
	}

	private TokenService tokenService(TokenRepository repo, CipherPassword cipherPassword, ClientRegistrationRepository clientRegistrationRepository) {
		return new TokenService(repo, cipherPassword, clientRegistrationRepository);
	}

	private OAuth2AuthorizedClientService clientService(TokenService tokenService) {
		return new ShopifyOAuth2AuthorizedClientService(tokenService);
	}

}
