package com.ppublica.shopify.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;
import com.ppublica.shopify.security.repository.TokenRepository;


@Configuration
public class SecurityBeansConfig {
	
	public static final String SHOPIFY_REGISTRATION_ID = "shopify";
	
	@Autowired
	private TokenRepository tokenRepository;
	
	@Bean
	CipherPassword cipherPassword(@Value("${ppublica.security.cipher.password}") String password) {
		return new CipherPassword(password);
	}
	
	
	@Bean
	OAuth2UserService<OAuth2UserRequest, OAuth2User> userService() {
		return new DefaultShopifyUserService();
	}
	
	
	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		return new ShopifyAuthorizationCodeTokenResponseClient();
	}
	
	
	@Bean
	public AuthenticationSuccessHandler successHandler() {
		return new NoRedirectSuccessHandler();
	}
	
	
	@Bean
    public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration shopifyClientRegistration) {
        return new InMemoryClientRegistrationRepository(shopifyClientRegistration);
    }
	
	// used by AuthenticatedPrincipalOAuth2AuthorizedClientRepository
	@Bean
	public OAuth2AuthorizedClientService clientService(TokenService tokenService) {
		return new ShopifyOAuth2AuthorizedClientService(tokenService);
	}
	
	@Bean
	public OAuth2AuthorizationRequestResolver shopifyOauth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
		return new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository(), ShopifySecurityConfigurer.INSTALL_PATH, ShopifySecurityConfigurer.LOGIN_ENDPOINT);
	}
	
	@Bean
	public ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository() {
		return new ShopifyHttpSessionOAuth2AuthorizationRequestRepository(ShopifySecurityConfigurer.INSTALL_PATH);
	}
	
	@Bean
	public TokenService tokenService(CipherPassword cipherPassword, ClientRegistrationRepository clientRegistrationRepository) {
		return new TokenService(this.tokenRepository, cipherPassword, clientRegistrationRepository);
	}
	

	@Bean
	protected ClientRegistration shopifyClientRegistration(@Value("${ppublica.shopify.client.client_id}")String clientId,
			 @Value("${ppublica.shopify.client.client_secret}")String clientSecret, 
			 @Value("${ppublica.shopify.client.scope}")String scope) {
		

        return ClientRegistration.withRegistrationId(SHOPIFY_REGISTRATION_ID)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}" + ShopifySecurityConfigurer.AUTHORIZATION_REDIRECT_PATH + "/{registrationId}")
            .scope(scope.split(","))
            .authorizationUri("https://{shop}/admin/oauth/authorize")
            .tokenUri("https://{shop}/admin/oauth/access_token")
            .clientName("Shopify")
            .build();
    }
	
	@Bean
	public ShopifyVerificationStrategy shopifyVerficationStrategy(ClientRegistrationRepository clientRegistrationRepository) {
		return new ShopifyVerificationStrategy(clientRegistrationRepository, customAuthorizationRequestRepository());
	}
	
	@Bean
	public CsrfTokenRepository csrfTokenRepository() {
		CookieCsrfTokenRepository repo = new CookieCsrfTokenRepository();
		repo.setCookieHttpOnly(false);
		
		return repo;
	}

}