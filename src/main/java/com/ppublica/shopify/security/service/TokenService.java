package com.ppublica.shopify.security.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

/**
 * Provides methods to interact with the TokenRepository to get, save, update, or delete a store.
 * 
 * @see ShopifyOAuth2AuthorizedClientService
 */
public class TokenService {
	private final Log logger = LogFactory.getLog(TokenService.class);
	
	/**
	 * The parameter name that holds the shop domain in a request to the "installation" path.
	 */
	public static final String SHOP_ATTRIBUTE_NAME = "shop";
	
	private TokenRepository tokenRepository;
	private CipherPassword cipherPassword;
	private ClientRegistrationRepository clientRepository;
	private PersistedStoreAccessTokenUtility persistedAccessTokenUtility = new PersistedStoreAccessTokenUtility();
	
	/**
	 * Build a new TokenService.
	 * 
	 * @param tokenRepository The TokenRepository
	 * @param cipherPassword The CipherPassword
	 * @param clientRepository The ClientRegistrationRepository
	 */
	public TokenService(TokenRepository tokenRepository, CipherPassword cipherPassword, ClientRegistrationRepository clientRepository) {
		this.tokenRepository = tokenRepository;
		this.cipherPassword = cipherPassword;
		this.clientRepository = clientRepository;

	}
	
	
	/**
	 * Save a new store. It uses an OAuth2AuthorizedClient with a raw token to create an encrypted token 
	 * to persist.
	 * 
	 * @param authorizedClient The OAuth2AuthorizedClient with credentials.
	 * @param principal The OAuth2AuthenticationToken that contains the user info
	 */
	public void saveNewStore(OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken principal) {
		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);

		PersistedStoreAccessToken token = persistedAccessTokenUtility.fromAuthenticationObjectsToPersistedStoreAccessToken(authorizedClient, principal, encryptedTokenAndSalt);
				
		this.tokenRepository.saveNewStore(token);
		
	}
	
	
	/**
	 * Checks for the existence of a store that matches the provided storeDomain String.
	 * 
	 * @param shopDomain The full shop domain
	 * @return true if store exists, false otherwise
	 */
	public boolean doesStoreExist(String shopDomain) {
		PersistedStoreAccessToken token = this.tokenRepository.findTokenForStore(shopDomain);
		
		if(token != null) {
			return true;
		}
		
		return false;
	}


	/**
	 * Returns a OAuth2AuthorizedClient if and only if it finds a store that matches the shopDomain.
	 * If there's a problem decrypting the token for the store, null is returned.
	 * 
	 * @param shopDomain The full shop domain
	 * @return The OAuth2AuthorizedClient representing the store, or null
	 */
	public OAuth2AuthorizedClient getStore(String shopDomain) {
		
		PersistedStoreAccessToken ets = this.tokenRepository.findTokenForStore(shopDomain);
		
		if(ets == null) {
			return null;
		}
		
		// obtain a representation of the raw token
		DecryptedTokenAndSalt decryptedTokenAndSalt = getRawToken(ets);
		
		if(decryptedTokenAndSalt == null) {
			logger.info("The salt and encrypted passwords are out of date/corrupted");
			return null;
		}
		
		ClientRegistration cr = clientRepository.findByRegistrationId(SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		
		if(cr == null) {
			throw new RuntimeException("An error occurred retrieving the ClientRegistration for " + SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		}
		
		OAuth2AuthorizedClient client = persistedAccessTokenUtility.fromPersistedStoreAccessTokenToOAuth2AuthorizedClient(ets, decryptedTokenAndSalt, cr);

		return client;
	
		
	}
	
	
	/**
	 * Updates the store info for an an existing store. 
	 * 
	 * @param authorizedClient The OAuth2AuthorizedClient with credentials.
	 * @param principal The OAuth2AuthenticationToken that contains the user info
	 */
	public void updateStore(OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken principal) {
		
		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);
		
		PersistedStoreAccessToken token = persistedAccessTokenUtility.fromAuthenticationObjectsToPersistedStoreAccessToken(authorizedClient, principal, encryptedTokenAndSalt);

		
		this.tokenRepository.updateStore(token);

	}
	
	/**
	 * Calls TokenRepository to uninstall the store that matches the shopDomain.
	 * 
	 * @param shopDomain The full domain of the store to be uninstalled
	 */
	public void uninstallStore(String shopDomain) {
		if(shopDomain != null && !shopDomain.isEmpty()) {
			this.tokenRepository.uninstallStore(shopDomain);
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

