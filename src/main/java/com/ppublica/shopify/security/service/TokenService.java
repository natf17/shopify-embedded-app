package com.ppublica.shopify.security.service;

import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;
import com.ppublica.shopify.security.repository.PersistedStoreAccessToken;
import com.ppublica.shopify.security.repository.PersistedStoreAccessTokenUtility;
import com.ppublica.shopify.security.repository.TokenRepository;

/*
 * Used by:
 * 
 * ShopifyOAuth2AuthorizedClientService
 */
public class TokenService {
	
	public static final String SHOP_ATTRIBUTE_NAME = "shop";
	
	private TokenRepository tokenRepository;
	private CipherPassword cipherPassword;
	private ClientRegistrationRepository clientRepository;
	private PersistedStoreAccessTokenUtility persistedAccessTokenUtility = new PersistedStoreAccessTokenUtility();
	
	public TokenService(TokenRepository tokenRepository, CipherPassword cipherPassword, ClientRegistrationRepository clientRepository) {
		this.tokenRepository = tokenRepository;
		this.cipherPassword = cipherPassword;
		this.clientRepository = clientRepository;

	}
	
	/*
	 * Expects an OAuth2AuthorizedClient with a raw token to create an encrypted token to persist.
	 * 
	 * It uses the OAuth2AuthorizedClient, OAuth2AuthenticationToken, and EncryptedTokenAndSalt to
	 * save the store.
	 * 
	 */
	public void saveNewStore(OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken principal) {
		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);

		PersistedStoreAccessToken token = persistedAccessTokenUtility.fromAuthenticationObjectsToPersistedStoreAccessToken(authorizedClient, principal, encryptedTokenAndSalt);
		
		this.tokenRepository.saveNewStore(token);
		
	}
	
	// returns true if a store with this name exists, regardless of validity of stored credentials
	public boolean doesStoreExist(String storeDomain) {
		PersistedStoreAccessToken token = this.tokenRepository.findTokenForStore(storeDomain);
		
		if(token != null) {
			return true;
		}
		
		return false;
	}

	// will return an existing, valid store
	public OAuth2AuthorizedClient getStore(String storeDomain) {
		
		PersistedStoreAccessToken ets = this.tokenRepository.findTokenForStore(storeDomain);
		
		if(ets == null) {
			return null;
		}
		
		// obtain a representation of the raw token
		DecryptedTokenAndSalt decryptedTokenAndSalt = getRawToken(ets);
		
		if(decryptedTokenAndSalt == null) {
			// the salt and encrypted passwords are out of date
			return null;
		}
		
		ClientRegistration cr = clientRepository.findByRegistrationId(SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		
		if(cr == null) {
			throw new RuntimeException("An error occurred retrieving the ClientRegistration for " + SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		}
		
		OAuth2AuthorizedClient client = persistedAccessTokenUtility.fromPersistedStoreAccessTokenToOAuth2AuthorizedClient(ets, decryptedTokenAndSalt, cr);

		return client;
	
		
	}
	
	
	
	
	
	public void updateStore(OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken principal) {
		
		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);
		
		PersistedStoreAccessToken token = persistedAccessTokenUtility.fromAuthenticationObjectsToPersistedStoreAccessToken(authorizedClient, principal, encryptedTokenAndSalt);

		
		this.tokenRepository.updateStore(token);

	}
	
	public void uninstallStore(String storeDomain) {
		if(storeDomain != null && !storeDomain.isEmpty()) {
			this.tokenRepository.uninstallStore(storeDomain);
		}
	}
	
	public void setPersistedStoreAccessTokenUtility(PersistedStoreAccessTokenUtility customPersistedAccessTokenUtility) {
		this.persistedAccessTokenUtility = customPersistedAccessTokenUtility;
	}
	
	
	/*
	 * Returns null if there is an inconsistency in the salts or passwords
	 */
	private DecryptedTokenAndSalt getRawToken(PersistedStoreAccessToken storeAccessToken) {
		
		EncryptedTokenAndSalt etS = storeAccessToken.getTokenAndSalt();
		if(etS == null) {
			return null;
		}
		
		String salt = etS.getSalt();
		if(salt == null || salt.isEmpty()) {
			return null;
		}
		
		String encToken = etS.getEncryptedToken();
		if(encToken == null || encToken.isEmpty()) {
			return null;
		}
		
		String decryptedToken = decryptToken(etS);
		
		if(decryptedToken == null) {
			return null;
		}
		
		return new DecryptedTokenAndSalt(decryptedToken, salt);
		
	}
	
	private EncryptedTokenAndSalt getTokenAndSalt(OAuth2AuthorizedClient authorizedClient) {
		
		String rawAccessTokenValue = authorizedClient.getAccessToken().getTokenValue();
		
		String genSalt = KeyGenerators.string().generateKey();
		
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), genSalt);
		
		return new EncryptedTokenAndSalt(encryptor.encrypt(rawAccessTokenValue), genSalt);
		
	}
	
	
	private String decryptToken(EncryptedTokenAndSalt enC) {
		TextEncryptor textEncryptor = Encryptors.queryableText(cipherPassword.getPassword(), enC.getSalt());
		
		String decryptedToken = null;
		try {
			decryptedToken = textEncryptor.decrypt(enC.getEncryptedToken());
		} catch(Exception e) {
			// the cipher password changed...
			
		}
		return decryptedToken;
		
		
	}
	

}

