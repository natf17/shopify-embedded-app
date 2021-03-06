package com.ppublica.shopify.security.repository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import com.ppublica.shopify.security.service.DecryptedTokenAndSalt;
import com.ppublica.shopify.security.service.EncryptedTokenAndSalt;


/**
 * A utility class with methods to transform service objects (OAuth2AuthorizedClient, OAuth2AuthenticationToken, 
 * EncryptedTokenAndSalt) to repository/entity objects (PersistedStoreAccessToken), and vice versa.
 * 
 * @author N F
 * @see com.ppublica.shopify.security.service.TokenService
 */
public class PersistedStoreAccessTokenUtility {

	/**
	 * Create a PersistedStoreAccessToken from OAuth2AuthorizedClient, OAuth2AuthenticationToken, and 
	 * EncryptedTokenAndSalt.
	 * 
	 * @param authorizedClient The OAuth2AuthorizedClient with a ClientRegistration, principalName, and OAuth2AccessToken
	 * @param principal The OAuth2AuthenticationToken with a OAuth2User, authorities, and registrationId from ClientRegistation
	 * @param encryptedToken The encrypted token
	 * @return The PersistedStoreAccessToken to store in the database
	 */
	public PersistedStoreAccessToken fromAuthenticationObjectsToPersistedStoreAccessToken(OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken principal, EncryptedTokenAndSalt encryptedToken) {

		String storeDomain = principal.getPrincipal().getName();
		
		OAuth2AccessToken oauth2AccessToken = authorizedClient.getAccessToken();
		
		Instant expiresAt = oauth2AccessToken.getExpiresAt();
		Long expires = expiresAt != null ? expiresAt.truncatedTo(ChronoUnit.SECONDS).getEpochSecond() : null;
		
		Instant issuedAt = oauth2AccessToken.getIssuedAt();
		Long issued = issuedAt != null ? issuedAt.truncatedTo(ChronoUnit.SECONDS).getEpochSecond() : null;


		PersistedStoreAccessToken persistedToken = new PersistedStoreAccessToken();
		persistedToken.setStoreDomain(storeDomain);
		persistedToken.setExpiresAt(expires);
		persistedToken.setIssuedAt(issued);
		persistedToken.setScopes(oauth2AccessToken.getScopes());
		persistedToken.setTokenAndSalt(encryptedToken);
		persistedToken.setTokenType(oauth2AccessToken.getTokenType().getValue());

		
		return persistedToken;
	}
	
	
	/**
	 * Creates a fully populated OAuth2AuthorizedClient from PersistedStoreAccessToken, DecryptedTokenAndSalt, 
	 * and ClientRegistration.
	 *  
	 * @param storeAccessToken The PersistedStoreAccessToken
	 * @param decryptedTokenAndSalt The raw OAuth token
	 * @param cR The ClientRegistration
	 * @return A fully populated OAuth2AuthorizedClient
	 */
	public OAuth2AuthorizedClient fromPersistedStoreAccessTokenToOAuth2AuthorizedClient(PersistedStoreAccessToken storeAccessToken, DecryptedTokenAndSalt decryptedTokenAndSalt, ClientRegistration cR) {
		String store_domain = storeAccessToken.getStoreDomain();
		if(store_domain == null || store_domain.isEmpty()) {
			throw new RuntimeException("The store domain cannot be null");
		}
		
		String tokenType = storeAccessToken.getTokenType();
		if(!tokenType.equalsIgnoreCase("BEARER")) {
			throw new RuntimeException("A BEARER token is required.");
		}
		
		// construct a OAuth2AccessToken with decrypted values
		OAuth2AccessToken rawToken = new OAuth2AccessToken(
										 OAuth2AccessToken.TokenType.BEARER,
										 decryptedTokenAndSalt.getDecryptedToken(),
										 Instant.ofEpochSecond(storeAccessToken.getIssuedAt()).truncatedTo(ChronoUnit.SECONDS),
										 Instant.ofEpochSecond(storeAccessToken.getExpiresAt()).truncatedTo(ChronoUnit.SECONDS),
										 storeAccessToken.getScopes());
		return new OAuth2AuthorizedClient(
				cR,
				store_domain,
				rawToken,
				null);

	}
	

}
