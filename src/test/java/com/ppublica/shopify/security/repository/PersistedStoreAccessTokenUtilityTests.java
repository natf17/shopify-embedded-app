package com.ppublica.shopify.security.repository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.ppublica.shopify.security.service.DecryptedTokenAndSalt;
import com.ppublica.shopify.security.service.EncryptedTokenAndSalt;
import com.ppublica.shopify.security.service.ShopifyStore;


public class PersistedStoreAccessTokenUtilityTests {
	
	PersistedStoreAccessTokenUtility utility = new PersistedStoreAccessTokenUtility();

	// needed for OAuth2AuthorizedClient
	ClientRegistration clientRegistration;
	String principalName;
	OAuth2AccessToken accessToken;
	
	// needed for OAuth2AuthenticationToken
	OAuth2User principal;
	Collection<GrantedAuthority> authorities;
	String registrationId;
	
	Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
	Instant expiresAt = issuedAt.plusSeconds(1000L).truncatedTo(ChronoUnit.SECONDS);
	
	@Before
	public void setup() {
		this.clientRegistration = ClientRegistration.withRegistrationId("shopify")
        .clientId("client-id")
        .clientSecret("client-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
        .scope(new String[]{"read", "write"})
        .authorizationUri("https://{shop}/admin/oauth/authorize")
        .tokenUri("https://{shop}/admin/oauth/access_token")
        .clientName("Shopify")
        .build();
		
		this.principalName = "test-store.myshopify.com";
		
		this.accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "raw-token", issuedAt, expiresAt, new HashSet<>(Arrays.asList("read", "write")));
		
		Collection<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("read"), new SimpleGrantedAuthority("write"));

		this.principal = new ShopifyStore(principalName, "raw-token", "client-id", authorities);
		this.authorities = authorities;
		this.registrationId = "shopify";
		
	}
	
	@Test
	public void fromAuthenticationObjectsToPersistedStoreAccessTokenGivenCorrectArgumentsThenReturnsToken() {
		OAuth2AuthorizedClient client = new OAuth2AuthorizedClient(clientRegistration, principalName, accessToken);
		OAuth2AuthenticationToken authToken = new OAuth2AuthenticationToken(principal, authorities, registrationId);

		PersistedStoreAccessToken tok = utility.fromAuthenticationObjectsToPersistedStoreAccessToken(client, authToken, new EncryptedTokenAndSalt("enc-token", "salt"));
		
		Assert.assertTrue(expiresAt.getEpochSecond() == tok.getExpiresAt());
		Assert.assertEquals(2, tok.getScopes().size());
		Assert.assertEquals("test-store.myshopify.com", tok.getStoreDomain());
		Assert.assertEquals("enc-token", tok.getTokenAndSalt().getEncryptedToken());
		Assert.assertEquals("salt", tok.getTokenAndSalt().getSalt());
		Assert.assertEquals("Bearer", tok.getTokenType());
		
	}
	
	@Test
	public void fromPersistedStoreAccessTokenToOAuth2AuthorizedClientGivenCorrectArgumentsThenReturnsClient() {
		PersistedStoreAccessToken persistedToken = new PersistedStoreAccessToken();
		persistedToken.setStoreDomain("test-store.myshopify.com");
		persistedToken.setExpiresAt(expiresAt.getEpochSecond());
		persistedToken.setIssuedAt(issuedAt.getEpochSecond());
		persistedToken.setScopes(new HashSet<>(Arrays.asList("read", "write")));
		persistedToken.setTokenAndSalt(new EncryptedTokenAndSalt("enc-token", "salt"));
		persistedToken.setTokenType("Bearer");
		
		DecryptedTokenAndSalt decr = new DecryptedTokenAndSalt("dec-token", "salt");
		
		OAuth2AuthorizedClient client = utility.fromPersistedStoreAccessTokenToOAuth2AuthorizedClient(persistedToken, decr, clientRegistration);

		OAuth2AccessToken accessToken = client.getAccessToken();
		ClientRegistration cr = client.getClientRegistration();
		String principalName = client.getPrincipalName();

		
		
		Assert.assertEquals("dec-token", accessToken.getTokenValue());
		Assert.assertEquals(expiresAt, accessToken.getExpiresAt());
		Assert.assertEquals(issuedAt, accessToken.getIssuedAt());
		Assert.assertEquals(2, accessToken.getScopes().size());
		Assert.assertTrue(accessToken.getScopes().contains("read"));
		Assert.assertTrue(accessToken.getScopes().contains("write"));
		Assert.assertEquals("Bearer", accessToken.getTokenType().getValue());
		
		Assert.assertEquals("shopify", cr.getRegistrationId());
		
		Assert.assertEquals("test-store.myshopify.com", principalName);

	}
}
