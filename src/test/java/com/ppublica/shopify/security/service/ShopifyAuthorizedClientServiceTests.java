package com.ppublica.shopify.security.service;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;


public class ShopifyAuthorizedClientServiceTests {
	
	@Test
	public void loadAuthorizedClientWhenStoreExistsReturnsStore() {
		TokenService repo = mock(TokenService.class);
		OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
		when(repo.getStore("test-store")).thenReturn(client);
		
		ShopifyOAuth2AuthorizedClientService service = new ShopifyOAuth2AuthorizedClientService(repo);
		
		Assert.assertEquals(client, service.loadAuthorizedClient("reg-id", "test-store"));
		
	}
	
	@Test
	public void loadAuthorizedClientWhenStoreDoesntExistThenReturnNull() {
		TokenService repo = mock(TokenService.class);
		when(repo.getStore("test-store")).thenReturn(null);
		
		ShopifyOAuth2AuthorizedClientService service = new ShopifyOAuth2AuthorizedClientService(repo);
		
		Assert.assertNull(service.loadAuthorizedClient("reg-id", "test-store"));
		
	}
	
	@Test
	public void saveAuthorizedClientWhenStoreDoesntExistThenSaveStore() {
		TokenService repo = mock(TokenService.class);
		when(repo.doesStoreExist("test-store")).thenReturn(false);

		OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
		
		OAuth2AuthenticationToken token = mock(OAuth2AuthenticationToken.class);
		OAuth2User pr = mock(OAuth2User.class);
		when(pr.getName()).thenReturn("test-store");
		when(token.getPrincipal()).thenReturn(pr);
		
		
		ShopifyOAuth2AuthorizedClientService service = new ShopifyOAuth2AuthorizedClientService(repo);
		service.saveAuthorizedClient(client, token);
		
		verify(repo).saveNewStore(client, token);
		
	}
	
	@Test
	public void saveAuthorizedClientWhenStoreExistsThenUpdateStore() {
		TokenService repo = mock(TokenService.class);
		when(repo.doesStoreExist("test-store")).thenReturn(true);

		OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
		
		OAuth2AuthenticationToken token = mock(OAuth2AuthenticationToken.class);
		OAuth2User pr = mock(OAuth2User.class);
		when(pr.getName()).thenReturn("test-store");
		when(token.getPrincipal()).thenReturn(pr);
		
		
		ShopifyOAuth2AuthorizedClientService service = new ShopifyOAuth2AuthorizedClientService(repo);
		service.saveAuthorizedClient(client, token);
		
		verify(repo).updateStore(client, token);
		
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void saveAuthorizedClientWhenIncorrectThenThrowsException() {
		TokenService repo = mock(TokenService.class);
		OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
		Authentication pr = mock(Authentication.class);
	
		ShopifyOAuth2AuthorizedClientService service = new ShopifyOAuth2AuthorizedClientService(repo);
		
		service.saveAuthorizedClient(client, pr);
				
	}
	
	@Test
	public void removeAuthorizedClientDelegatesToTokenService() {
		TokenService repo = mock(TokenService.class);
		
		ShopifyOAuth2AuthorizedClientService service = new ShopifyOAuth2AuthorizedClientService(repo);
		service.removeAuthorizedClient("shopify", "test-store");

		verify(repo).uninstallStore("test-store");
		
				
	}


}
