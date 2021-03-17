package com.ppublica.shopify.security.configuration;

import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configurer.delegates.*;
import com.ppublica.shopify.security.repository.ShopifyTokenRepositoryImpl;
import com.ppublica.shopify.security.repository.TokenRepository;
import com.ppublica.shopify.security.service.ShopifyOAuth2AuthorizedClientService;
import com.ppublica.shopify.security.service.TokenService;
import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;


/**
 * A configuration class that adds all Shopify-security related beans.
 *
 * <p>Requires the following beans to be in the ApplicationContext:</p>
 * <ul>
 * 	<li>JdbcTemplate</li>
 * </ul>
 *
 *
 *
 * <p>Beans created:</p>
 * <ul>
 * 	<li>TokenRepository</li>
 * 	<li>ShopifyPaths</li>
 * 	<li>CipherPassword</li>
 * 	<li>OAuth2UserService&lt;OAuth2UserRequest, OAuth2User&gt;</li>
 * 	<li>OAuth2AccessTokenResponseClient&lt;OAuth2AuthorizationCodeGrantRequest&gt;</li>
 * 	<li>AuthorizationSuccessPageStrategy</li>
 * 	<li>AuthenticationSuccessHandler</li>
 * 	<li>ClientRegistration</li>
 * 	<li>ClientRegistrationRepository</li>
 * 	<li>TokenService</li>
 * 	<li>OAuth2AuthorizedClientService</li>
 * 	<li>ShopifyHttpSessionOAuth2AuthorizationRequestRepository</li>
 * 	<li>OAuth2AuthorizationRequestResolver</li>
 * 	<li>ShopifyVerificationStrategy</li>
 * 	<li>CsrfTokenRepository</li>
 * 	<li>ShopifyHeaders</li>
 * 	<li>ShopifyChannelSecurity</li>
 * 	<li>ShopifyCsrf</li>
 * 	<li>ShopifyLogout</li>
 * 	<li>ShopifyOAuth2</li>
 * </ul>
 *
 * <p>The following properties are searched to populate several objects:</p>
 *
 * <ul>
 * 	<li>ppublica.shopify.security.endpoints.install=</li>
 * 	<li>ppublica.shopify.security.endpoints.authorization-redirect=</li>
 * 	<li>ppublica.shopify.security.endpoints.login=</li>
 * 	<li>ppublica.shopify.security.endpoints.logout=</li>
 * 	<li>ppublica.shopify.security.endpoints.authentication-failure=</li>
 * 	<li>ppublica.shopify.security.endpoints.uninstall=</li>
 * 	<li>ppublica.shopify.security.endpoints.enable-default-info-page=</li>
 * 	<li>ppublica.shopify.security.endpoints.menu-link=</li>
 *
 * 	<li>ppublica.shopify.security.cipher.password= **required**</li>
 *
 * 	<li>ppublica.shopify.security.client.client_id= **required**</li>
 * 	<li>ppublica.shopify.security.client.client_secret= **required**</li>
 * 	<li>ppublica.shopify.security.client.scope= **required**</li>
 * </ul>
 *
 * @author N F
 *
 */
@Configuration
public class SecurityBeansConfig {
	private final Log logger = LogFactory.getLog(SecurityBeansConfig.class);

	public static final String SHOPIFY_REGISTRATION_ID = "shopify";


	@Bean
	public TokenRepository getTokenRepository(JdbcTemplate jdbc) {
		ShopifyTokenRepositoryImpl repo = new ShopifyTokenRepositoryImpl();
		repo.setJdbc(jdbc);

		return repo;
	}

	@Bean
	public ShopifyPaths shopifyPaths(@Value("${ppublica.shopify.security.endpoints.install:}") String installPath,
							  @Value("${ppublica.shopify.security.endpoints.authorization-redirect:}") String authorizationRedirectPath,
							  @Value("${ppublica.shopify.security.endpoints.login:}") String loginEndpoint,
							  @Value("${ppublica.shopify.security.endpoints.logout:}") String logoutEndpoint,
							  @Value("${ppublica.shopify.security.endpoints.authentication-failure:}") String authenticationFailureUri,
							  @Value("${ppublica.shopify.security.endpoints.uninstall:}") String uninstallUri,
							  @Value("${ppublica.shopify.security.endpoints.enable-default-info-page:}") String enableDefaultInfoPage,
							  @Value("${ppublica.shopify.security.endpoints.menu-link:}") String menuLink) {

		if(logger.isDebugEnabled()) {
			logger.debug("***Paths read from environment: ***");
			logger.debug("Installation:           " + installPath);
			logger.debug("Authorization redirect: " + authorizationRedirectPath);
			logger.debug("Login:                  " + loginEndpoint);
			logger.debug("Logout:                 " + logoutEndpoint);
			logger.debug("Authentication failure: " + authenticationFailureUri);
			logger.debug("Uninstallation path:    " + uninstallUri);
			logger.debug("Should enable app info: " + enableDefaultInfoPage);
			logger.debug("Menu link:              " + menuLink);

		}
		boolean enableDefaultInfo = false;
		if(enableDefaultInfoPage != null) {
			enableDefaultInfo = Boolean.parseBoolean(enableDefaultInfoPage);
		}
		return new ShopifyPaths(installPath, authorizationRedirectPath, loginEndpoint,
								logoutEndpoint, authenticationFailureUri, uninstallUri, enableDefaultInfo, menuLink);

	}


	@Bean
	public CipherPassword cipherPassword(@Value("${ppublica.shopify.security.cipher.password:#{null}}") String password) {
		if(password == null) {
			throw new RuntimeException("Cipher password is required! Set the property ppublica.shopify.security.cipher.password");
		}
		return new CipherPassword(password);
	}

	@Bean
	protected ClientRegistration shopifyClientRegistration(@Value("${ppublica.shopify.security.client.client_id:#{null}}")String clientId,
			 @Value("${ppublica.shopify.security.client.client_secret:#{null}}")String clientSecret,
			 @Value("${ppublica.shopify.security.client.scope:#{null}}")String scope,
			 ShopifyPaths shopifyPaths) {

		if(clientId == null) {
			throw new RuntimeException("Client id is required! Set the property ppublica.shopify.security.client.client_id");
		}

		if(clientSecret == null) {
			throw new RuntimeException("Client secret is required! Set the property ppublica.shopify.security.client.client_secret");
		}

		if(scope == null) {
			throw new RuntimeException("Scope is required! Set the property publica.shopify.security.client.scope");
		}

        return ClientRegistration.withRegistrationId(SHOPIFY_REGISTRATION_ID)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}" + shopifyPaths.getAuthorizationRedirectPath() + "/{registrationId}")
            .scope(scope.split(","))
            .authorizationUri("https://{shop}/admin/oauth/authorize")
            .tokenUri("https://{shop}/admin/oauth/access_token")
            .clientName("Shopify")
            .build();
    }

	@Bean
	public TokenService tokenService(TokenRepository repo, CipherPassword cipherPassword, ClientRegistrationRepository clientRegistrationRepository) {
		return new TokenService(repo, cipherPassword, clientRegistrationRepository);
	}

	// used by AuthenticatedPrincipalOAuth2AuthorizedClientRepository
	@Bean
	public OAuth2AuthorizedClientService clientService(TokenService tokenService) {
		return new ShopifyOAuth2AuthorizedClientService(tokenService);
	}

	@Bean
	public ShopifyVerificationStrategy shopifyVerficationStrategy(ClientRegistrationRepository clientRegistrationRepository,
					ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository) {
		return new ShopifyVerificationStrategy(clientRegistrationRepository, customAuthorizationRequestRepository);
	}


	@Bean
	public CsrfTokenRepository csrfTokenRepository() {
		CookieCsrfTokenRepository repo = new CookieCsrfTokenRepository();
		repo.setCookieHttpOnly(false);

		return repo;
	}

	@Bean
	public ShopifyHeaders shopifyHeaders() {
		return new ShopifyHeaders();
	}

	@Bean
	public ShopifyChannelSecurity shopifyChannelSecurity() {
		return new ShopifyChannelSecurity();
	}

	@Bean
	public ShopifyCsrf shopifyCsrf(ShopifyPaths shopifyPaths, CsrfTokenRepository csrfTokenRepo) {
		return new ShopifyCsrf(shopifyPaths.getUninstallUri(), csrfTokenRepo);
	}

	@Bean
	public ShopifyLogout shopifyLogout(ShopifyPaths shopifyPaths) {
		return new ShopifyLogout(shopifyPaths.getLoginEndpoint(), shopifyPaths.getLogoutEndpoint());
	}

	@Bean
	public ShopifyOAuth2 shopifyOAuth2(ShopifyPaths shopifyPaths, ClientRegistration shopifyClientRegistration) {
		return new ShopifyOAuth2(shopifyPaths, shopifyClientRegistration);
	}
}