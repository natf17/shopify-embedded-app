package com.ppublica.shopify.security.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import com.ppublica.shopify.security.service.DefaultShopifyUserService;
import com.ppublica.shopify.security.service.ShopifyOAuth2AuthorizedClientService;
import com.ppublica.shopify.security.service.TokenService;
import com.ppublica.shopify.security.web.NoRedirectSuccessHandler;
import com.ppublica.shopify.security.web.ShopifyAuthorizationCodeTokenResponseClient;
import com.ppublica.shopify.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;
import com.ppublica.shopify.security.web.ShopifyOAuth2AuthorizationRequestResolver;
import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;
import com.ppublica.shopify.security.configurer.delegates.ShopifyChannelSecurity;
import com.ppublica.shopify.security.configurer.delegates.ShopifyCsrf;
import com.ppublica.shopify.security.configurer.delegates.ShopifyHeaders;
import com.ppublica.shopify.security.configurer.delegates.ShopifyLogout;
import com.ppublica.shopify.security.configurer.delegates.ShopifyOAuth2;
import com.ppublica.shopify.security.configurer.delegates.ShopifySessionAuthenticationStrategyConfigurer;
import com.ppublica.shopify.security.repository.ShopifyTokenRepositoryImpl;
import com.ppublica.shopify.security.repository.TokenRepository;

/*
 * ppublica.shopify.security.endpoints.install=
 * ppublica.shopify.security.endpoints.authorization-redirect=
 * ppublica.shopify.security.endpoints.login=
 * ppublica.shopify.security.endpoints.logout=
 * ppublica.shopify.security.endpoints.authentication-failure=
 * ppublica.shopify.security.endpoints.uninstall=
 * ppublica.shopify.security.endpoints.enable-default-info-page=
 * 
 * ppublica.shopify.security.cipher.password=
 * 
 * ppublica.shopify.security.client.client_id=
 * ppublica.shopify.security.client.client_secret=
 * ppublica.shopify.security.client.scope=
 * 
 */
@Configuration
public class SecurityBeansConfig {
	
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
							  @Value("${ppublica.shopify.security.endpoints.enable-default-info-page:}") String enableDefaultInfoPage) {
		
		boolean enableDefaultInfo = false;
		if(enableDefaultInfoPage != null) {
			enableDefaultInfo = Boolean.parseBoolean(enableDefaultInfoPage);
		}
		return new ShopifyPaths(installPath, authorizationRedirectPath, loginEndpoint,
								logoutEndpoint, authenticationFailureUri, uninstallUri, enableDefaultInfo);
		
	}

	
	@Bean
	public CipherPassword cipherPassword(@Value("${ppublica.shopify.security.cipher.password:#{null}}") String password) {
		if(password == null) {
			throw new RuntimeException("Cipher password is required!");
		}
		return new CipherPassword(password);
	}
	
	
	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> userService() {
		return new DefaultShopifyUserService();
	}
	
	
	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		return new ShopifyAuthorizationCodeTokenResponseClient();
	}
	
	
	@Bean
	public AuthenticationSuccessHandler successHandler(ShopifyPaths shopifyPaths) {
		return new NoRedirectSuccessHandler(shopifyPaths.getAuthorizationRedirectPath());
	}
	
	
	@Bean
	protected ClientRegistration shopifyClientRegistration(@Value("${ppublica.shopify.security.client.client_id:#{null}}")String clientId,
			 @Value("${ppublica.shopify.security.client.client_secret:#{null}}")String clientSecret, 
			 @Value("${ppublica.shopify.security.client.scope:#{null}}")String scope,
			 ShopifyPaths shopifyPaths) {
		

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
    public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration shopifyClientRegistration) {
        return new InMemoryClientRegistrationRepository(shopifyClientRegistration);
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
	public ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository(ShopifyPaths shopifyPaths) {
		return new ShopifyHttpSessionOAuth2AuthorizationRequestRepository(shopifyPaths.getInstallPath());
	}
	
	
	@Bean
	public OAuth2AuthorizationRequestResolver shopifyOauth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
					ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository,
					ShopifyPaths shopifyPaths) {
		return new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, shopifyPaths.getInstallPath(), shopifyPaths.getLoginEndpoint());
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
	public ShopifyCsrf shopifyCsrf(ShopifyPaths shopifyPaths) {
		return new ShopifyCsrf(shopifyPaths.getUninstallUri());
	}
	
	@Bean
	public ShopifyLogout shopifyLogout(ShopifyPaths shopifyPaths) {
		return new ShopifyLogout(shopifyPaths.getLoginEndpoint(), shopifyPaths.getLogoutEndpoint());
	}
	
	@Bean
	public ShopifyOAuth2 shopifyOAuth2(ShopifyPaths shopifyPaths) {
		return new ShopifyOAuth2(shopifyPaths.getAnyAuthorizationRedirectPath(), shopifyPaths.getLoginEndpoint(), shopifyPaths.getAuthenticationFailureUri());
	}
	
	@Bean
	public ShopifySessionAuthenticationStrategyConfigurer shopifySessionAuthenticationStrategyConfigurer() {
		return new ShopifySessionAuthenticationStrategyConfigurer();
	}
		
	
}