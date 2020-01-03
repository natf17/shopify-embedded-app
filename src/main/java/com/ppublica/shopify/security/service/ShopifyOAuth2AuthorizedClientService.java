package com.ppublica.shopify.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;


/**
 * 
 * An implementation of OAuth2AuthorizedClientService that uses the custom TokenService to save the store in a database 
 * (instead of in memory), or to update the store credentials if this store has already been "installed".
 * 
 * <p>It's invoked by OAuth2LoginAuthenticationFilter indirectly when it invokes 
 * AuthenticatedPrincipalOAuth2AuthorizedClientRepository to save the OAuth2AuthorizedClient. It's also invoked by 
 * ShopifyExistingTokenFilter to see if, in an embedded app, the shop has already installed this app. It is 
 * found by OAuth2ClientConfigurerUtils.</p>
 * 
 * <p>This class replaces the default InMemoryOAuth2AuthorizedClientService. OAuth2ClientConfigurerUtils finds this bean when
 * building the OAuth2LoginFilter.</p>
 * 
 * <p>Note: Updating store credentials will only happen when ShopifyOAuth2AuthorizedClientService is called.
 * In an embedded app, it is only called once: when installing. Afterwards, log in directly from the browser to 
 * call it.</p>
 * 
 * @author N F
 * @see org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository
 * @see org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter
 * @see com.ppublica.shopify.security.filters.ShopifyExistingTokenFilter
 * 
 */
public class ShopifyOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {
	
	private TokenService tokenService;
	
	public ShopifyOAuth2AuthorizedClientService(TokenService tokenService) {
		this.tokenService = tokenService;
	}
	

	/**
	 * Load the store that matches the provided principalName. ShopifyExistingFilter calls this method to
	 * create an OAuth2AuthenticationToken.
	 * 
	 * @param clientRegistrationId The registration id (e.g. "shopify")
	 * @param principalName The full Shopify shop domain
	 * @return The OAuth2AuthorizedClient or null if store not found
	 */
	@SuppressWarnings("unchecked")
	@Override
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
			String principalName) {
		
		OAuth2AuthorizedClient client = tokenService.getStore(principalName);
		
		if(client != null) {
			return (T) client;

		}
		return null;
	}


	/**
	 * Decides whether it should update the database or add the new store based on whether or not this store
	 * exists already. OAuth2LoginAuthenticationFilter calls this methods upon successful authentication.
	 * 
	 * @param authorizedClient The authenticated OAuth2AuthorizedClient
	 * @param principal The OAuth2AuthenticationToken
	 */
	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		
		if(!OAuth2AuthenticationToken.class.isAssignableFrom(principal.getClass())) {
			throw new IllegalArgumentException("The principal must be of type OAuth2AuthenticationToken");
		}
		
		OAuth2AuthenticationToken pr = (OAuth2AuthenticationToken)principal;
		
		String shop = pr.getPrincipal().getName();
		
		boolean doesStoreExist = tokenService.doesStoreExist(shop);

		if(doesStoreExist) {
			tokenService.updateStore(authorizedClient, pr);
		} else {
			tokenService.saveNewStore(authorizedClient, pr);

		}
	
	}

	
	/**
	 * Permanently delete/uninstall the store that matches the shop domain/principalName.
	 * 
	 * @param clientRegistrationId The registration id (e.g. "shopify")
	 * @param principalName The full shop domain
	 */
	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
		tokenService.uninstallStore(principalName);
		
	}

}
