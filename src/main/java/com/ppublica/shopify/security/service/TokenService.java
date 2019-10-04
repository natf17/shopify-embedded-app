package com.ppublica.shopify.security.service;

import java.util.Set;


import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import com.ppublica.shopify.security.authentication.CipherPassword;
import com.ppublica.shopify.security.configuration.SecurityBeansConfig;
import com.ppublica.shopify.security.repository.EncryptedTokenAndSalt;
import com.ppublica.shopify.security.repository.TokenRepository;
import com.ppublica.shopify.security.repository.TokenRepository.OAuth2AccessTokenWithSalt;


public class TokenService {
	
	public static final String SHOP_ATTRIBUTE_NAME = "shop";
	
	private TokenRepository tokenRepository;
	private CipherPassword cipherPassword;
	private ClientRegistrationRepository clientRepository;
	
	public TokenService(TokenRepository tokenRepository, CipherPassword cipherPassword, ClientRegistrationRepository clientRepository) {
		this.tokenRepository = tokenRepository;
		this.cipherPassword = cipherPassword;
		this.clientRepository = clientRepository;

	}
	
	public void saveNewStore(OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken principal) {
		
		String shop = getStoreName(principal);
		
		Set<String> scopes = authorizedClient.getAccessToken().getScopes();
		
		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);

		this.tokenRepository.saveNewStore(shop, scopes, encryptedTokenAndSalt);	
		
	}
	
	// returns true if a store with this name exists, regardless of validity of stored credentials
	public boolean doesStoreExist(String shop) {
		OAuth2AccessTokenWithSalt token = this.tokenRepository.findTokenForRequest(shop);
		
		if(token != null) {
			return true;
		}
		
		return false;
	}

	// will return an existing, valid store
	public OAuth2AuthorizedClient getStore(String shopName) {
		
		OAuth2AccessTokenWithSalt ets = this.tokenRepository.findTokenForRequest(shopName);
		
		if(ets == null) {
			return null;
		}
		
		OAuth2AccessToken rawToken = getRawToken(ets);
		
		if(rawToken == null) {
			// the salt and encrypted passwords are out of date
			return null;
		}
		
		ClientRegistration cr = clientRepository.findByRegistrationId(SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		
		if(cr == null) {
			throw new RuntimeException("An error occurred retrieving the ClientRegistration for " + SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		}
		
		return new OAuth2AuthorizedClient(
				cr,
				shopName,
				rawToken,
				null);
		
	}
	
	
	
	
	
	public void updateStore(OAuth2AuthorizedClient authorizedClient, OAuth2AuthenticationToken principal) {
		
		String shop = getStoreName(principal);
		
		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);
		
		this.tokenRepository.updateKey(shop, encryptedTokenAndSalt);

	}
	
	public void uninstallStore(String store) {
		if(store != null && !store.isEmpty()) {
			this.tokenRepository.uninstallStore(store);
		}
	}
	
	
	
	private String getStoreName(OAuth2AuthenticationToken principal) {
		String shop = principal.getPrincipal().getName();

		return shop;
	}
	/*
	 * Returns null if there is an inconsistency in the salts or passwords
	 */
	private OAuth2AccessToken getRawToken(OAuth2AccessTokenWithSalt toS) {
		String salt = toS.getSalt();
		
		if(salt == null) {
			return null;
		}
		
		OAuth2AccessToken enTok = toS.getAccess_token();
		if(enTok == null) {
			return null;
		}
		
		String decryptedToken = decryptToken(new EncryptedTokenAndSalt(enTok.getTokenValue(), salt));
		
		if(decryptedToken == null) {
			return null;
		}
		
		return new OAuth2AccessToken(enTok.getTokenType(),
									 decryptedToken,
									 enTok.getIssuedAt(),
									 enTok.getExpiresAt(),
									 enTok.getScopes());
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

