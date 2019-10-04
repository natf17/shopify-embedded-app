package com.ppublica.shopify.security.service;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.never;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;
import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;
import com.ppublica.shopify.security.repository.EncryptedTokenAndSalt;
import com.ppublica.shopify.security.repository.TokenRepository;

public class TokenServiceTests {
	
	ClientRegistration clientRegistration;
	Collection <? extends GrantedAuthority> authorities;
	@Before
	public void setup() {
		clientRegistration = ClientRegistration.withRegistrationId("shopify")
	            .clientId("client-id")
	            .clientSecret("client-secret")
	            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
	            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	            .redirectUriTemplate("{baseUrl}" + ShopifySecurityConfigurer.AUTHORIZATION_REDIRECT_PATH + "/{registrationId}")
	            .scope("read_products write_products")
	            .authorizationUri("https://{shop}/admin/oauth/authorize")
	            .tokenUri("https://{shop}/admin/oauth/access_token")
	            .clientName("Shopify")
	            .build();
		
		authorities = new ArrayList<SimpleGrantedAuthority>(Arrays.asList(new SimpleGrantedAuthority("read"), new SimpleGrantedAuthority("write")));


	}
	
	@Test
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void saveNewStoreWhenSavingDelegatesToTokenRepository() {
		
		// create the TokenService
		TokenRepository repo = mock(TokenRepository.class);
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		
		CipherPassword cp = new CipherPassword("password");
		
		TokenService tS = new TokenService(repo, cp, cR);
		
		
		// configure arguments
		OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
		
		ShopifyStore store = new ShopifyStore("testStore.myshopify.com", "oauth-token", "client-api-key", authorities);
		
		when(authentication.getPrincipal()).thenReturn(store);
		
		OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
		OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
		Set<String> scopes = new HashSet<>(Arrays.asList("read", "write"));

		when(accessToken.getScopes()).thenReturn(scopes);
		when(accessToken.getTokenValue()).thenReturn("oauth-token");

		when(client.getAccessToken()).thenReturn(accessToken);
		
				
		ArgumentCaptor<String> shopName = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<Set> scopeSet = ArgumentCaptor.forClass(Set.class);
		
		ArgumentCaptor<EncryptedTokenAndSalt> et = ArgumentCaptor.forClass(EncryptedTokenAndSalt.class);
		
		
		// invoke method
		tS.saveNewStore(client, authentication);
		
		
		// assertions
		verify(repo, times(1)).saveNewStore(shopName.capture(), scopeSet.capture(), et.capture());
		
		Assert.assertEquals("testStore.myshopify.com", shopName.getValue());
		Assert.assertTrue(scopeSet.getValue().contains("read"));
		Assert.assertTrue(scopeSet.getValue().contains("write"));
		
		EncryptedTokenAndSalt resultEt = et.getValue();
		Assert.assertFalse(resultEt.getEncryptedToken().isEmpty());
		Assert.assertFalse(resultEt.getSalt().isEmpty());
	
		
	}
	
	@Test
	public void doesStoreExistWhenYesReturnsTrue() {
		// configure mocks for constructor args
		TokenRepository repo = mock(TokenRepository.class);
		TokenRepository.OAuth2AccessTokenWithSalt resp = mock(TokenRepository.OAuth2AccessTokenWithSalt.class);
		doReturn(resp).when(repo).findTokenForRequest("testStore.myshopify.com");

		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		
		CipherPassword cp = new CipherPassword("password");
		
		// create the TokenService
		TokenService tS = new TokenService(repo, cp, cR);

		// assertions
		Assert.assertTrue(tS.doesStoreExist("testStore.myshopify.com"));
		
	}
	
	@Test
	public void doesStoreExistWhenNoReturnsFalse() {
		// create the TokenService
		TokenRepository repo = mock(TokenRepository.class);
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		
		CipherPassword cp = new CipherPassword("password");
		
		TokenService tS = new TokenService(repo, cp, cR);		
		
		// assertions
		Assert.assertFalse(tS.doesStoreExist("testStore.myshopify.com"));
		
	}
	
	@Test
	public void getStoreWhenExistsReturnsOAuth2AuthorizedClient() {
		// configure constructor args
		CipherPassword cp = new CipherPassword("password");
		
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		doReturn(clientRegistration).when(cR).findByRegistrationId(SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
				
		
		// create the salt to encode the access token
		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cp.getPassword(), sampleSalt);
		String rawTokenValue = "raw-value";
		String encryptedTokenValue = encryptor.encrypt(rawTokenValue);

		// create an OAuth2AccessToken returned by the repo
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, encryptedTokenValue, Instant.now(), Instant.MAX);
		TokenRepository.OAuth2AccessTokenWithSalt repoResponse = new TokenRepository.OAuth2AccessTokenWithSalt(accessToken, sampleSalt);
				
		// configure the repo
		TokenRepository repo = mock(TokenRepository.class);
		doReturn(repoResponse).when(repo).findTokenForRequest("testStore.myshopify.com");
		

		// create the TokenService
		TokenService tS = new TokenService(repo, cp, cR);
		
		// invoke method
		OAuth2AuthorizedClient response = tS.getStore("testStore.myshopify.com");
		
		// obtain desired objects
		OAuth2AccessToken responseAccessToken = response.getAccessToken();
		
		// assertions
		Assert.assertEquals("testStore.myshopify.com", response.getPrincipalName());
		Assert.assertEquals("raw-value", responseAccessToken.getTokenValue());

	}
	
	@Test
	public void getStoreWhenDoesntExistReturnsNull() {
		// configure constructor args
		CipherPassword cp = new CipherPassword("password");
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);

		TokenRepository repo = mock(TokenRepository.class);
		doReturn(null).when(repo).findTokenForRequest("testStore.myshopify.com");
		
		// create the TokenService
		TokenService tS = new TokenService(repo, cp, cR);
		
		Assert.assertNull(tS.getStore("testStore.myshopify.com"));

	}
	
	@Test(expected=RuntimeException.class)
	public void getStoreWhenNoShopifyClientRegistrationThrowsException() {
		// configure constructor args
		CipherPassword cp = new CipherPassword("password");
				
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		doReturn(null).when(cR).findByRegistrationId(SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
						
				
		// create the salt to encode the access token
		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cp.getPassword(), sampleSalt);
		String rawTokenValue = "raw-value";
		String encryptedTokenValue = encryptor.encrypt(rawTokenValue);

		// create an OAuth2AccessToken returned by the repo
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, encryptedTokenValue, Instant.now(), Instant.MAX);
		TokenRepository.OAuth2AccessTokenWithSalt repoResponse = new TokenRepository.OAuth2AccessTokenWithSalt(accessToken, sampleSalt);
						
		// configure the repo
		TokenRepository repo = mock(TokenRepository.class);
		doReturn(repoResponse).when(repo).findTokenForRequest("testStore.myshopify.com");
				

		// create the TokenService
		TokenService tS = new TokenService(repo, cp, cR);
				
		// invoke method
		tS.getStore("testStore.myshopify.com");
	
		
	}
	
	@Test
	public void getStoreWhenSaltErrorReturnsNull() {
		// configure constructor args
		CipherPassword cp = new CipherPassword("password");
		
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		doReturn(clientRegistration).when(cR).findByRegistrationId(SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
				
		
		// create the salt to encode the access token
		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cp.getPassword(), sampleSalt);
		String rawTokenValue = "raw-value";
		String encryptedTokenValue = encryptor.encrypt(rawTokenValue) + "error";

		// create an OAuth2AccessToken returned by the repo
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, encryptedTokenValue, Instant.now(), Instant.MAX);
		TokenRepository.OAuth2AccessTokenWithSalt repoResponse = new TokenRepository.OAuth2AccessTokenWithSalt(accessToken, sampleSalt);
				
		// configure the repo
		TokenRepository repo = mock(TokenRepository.class);
		doReturn(repoResponse).when(repo).findTokenForRequest("testStore.myshopify.com");
		

		// create the TokenService
		TokenService tS = new TokenService(repo, cp, cR);
		
		// invoke method and assertion
		Assert.assertNull(tS.getStore("testStore.myshopify.com"));
		

	}
	
	@Test
	public void updateStoreWhenUpdatingDelegatesToTokenRepository() {
		
		// create the TokenService
		TokenRepository repo = mock(TokenRepository.class);
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		
		CipherPassword cp = new CipherPassword("password");
		
		TokenService tS = new TokenService(repo, cp, cR);
		
		
		// configure arguments
		OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
		
		ShopifyStore store = new ShopifyStore("testStore.myshopify.com", "oauth-token", "client-api-key", authorities);
		
		when(authentication.getPrincipal()).thenReturn(store);
		
		OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
		OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
		
		when(accessToken.getTokenValue()).thenReturn("oauth-token");

		when(client.getAccessToken()).thenReturn(accessToken);
		
				
		ArgumentCaptor<String> shopName = ArgumentCaptor.forClass(String.class);
		
		ArgumentCaptor<EncryptedTokenAndSalt> et = ArgumentCaptor.forClass(EncryptedTokenAndSalt.class);
		
		
		// invoke method
		tS.updateStore(client, authentication);
		
		
		// assertions
		verify(repo, times(1)).updateKey(shopName.capture(), et.capture());
		
		Assert.assertEquals("testStore.myshopify.com", shopName.getValue());
		
		EncryptedTokenAndSalt resultEt = et.getValue();
		Assert.assertFalse(resultEt.getEncryptedToken().isEmpty());
		Assert.assertFalse(resultEt.getSalt().isEmpty());
	
		
	}
	
	@Test
	public void uninstallStoreWhenValidStoreNameCallRepo() {
		
		// create the TokenService
		TokenRepository repo = mock(TokenRepository.class);
		
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		
		CipherPassword cp = new CipherPassword("password");
		
		TokenService tS = new TokenService(repo, cp, cR);
		
		// invoke method
		tS.uninstallStore("testStore.myshopify.com");
				
				
		// assertions
		verify(repo, times(1)).uninstallStore("testStore.myshopify.com");
		
		
	}
	
	@Test
	public void uninstallStoreWhenNoStoreNameDontCallRepo() {
		
		// create the TokenService
		TokenRepository repo = mock(TokenRepository.class);
		
		ClientRegistrationRepository cR = mock(ClientRegistrationRepository.class);
		
		CipherPassword cp = new CipherPassword("password");
		
		TokenService tS = new TokenService(repo, cp, cR);
		
		// invoke method
		tS.uninstallStore("");
				
				
		// assertions
		verify(repo, never()).uninstallStore(ArgumentMatchers.any());
		
		
	}

	

}
