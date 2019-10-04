package com.ppublica.shopify.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

/*
 * Invoked by OAuth2LoginAuthenticationFilter indirectly when it invokes 
 * AuthenticatedPrincipalOAuth2AuthorizedClientRepository to save the OAuth2AuthorizedClient.
 * It's also invoked by ShopifyExistingFilter to see if, in an embedded app, the shop has already installed this app
 * 
 * It replaces the default InMemoryOAuth2AuthorizedClientService (see OAuth2ClientConfigurerUtils)
 * 
 * This client service uses the custom tokenService to save the store in a database (instead of in memory),
 * or to update the store credentials if this store has already been "installed".
 *
 * 
 * When building the OAuth2LoginFilter, OAuth2ClientConfigurerUtils finds this bean.
 * 
 * Note: Updating store credentials will only happen when ShopifyOAuth2AuthorizedClientService is called.
 * In an embedded app, it is only called once: when installing. 
 * Afterwards, log in directly from the browser to call it.
 * 
 */
public class ShopifyOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {
	
	private TokenService tokenService;
	
	public ShopifyOAuth2AuthorizedClientService(TokenService tokenService) {
		this.tokenService = tokenService;
	}
	
	/*
	 * Used by ShopifyExistingFilter to create an OAuth2AuthenticationToken
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

	/*
	 * Called by OAuth2LoginAuthenticationFilter upon successful authentication
	 * 
	 * Decides whether or not it should update the DB or add the new store
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

	/*
	 * Permanently delete the store... uninstall
	 */
	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
		tokenService.uninstallStore(principalName);
		
	}

}
