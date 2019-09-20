package com.ppublica.shopify.security.repository;

import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

public interface TokenRepository {
	
	OAuth2AccessTokenWithSalt findTokenForRequest(String shop);
	void saveNewStore(String shop, Set<String>scopes, EncryptedTokenAndSalt encryptedTokenAndSalt);
	void updateKey(String shop, EncryptedTokenAndSalt encryptedTokenAndSalt);
	void uninstallStore(String storeName);
	
	static class OAuth2AccessTokenWithSalt {
		private final OAuth2AccessToken access_token;
		private final String salt;
		
		public  OAuth2AccessTokenWithSalt(OAuth2AccessToken access_token, String salt) {
			this.access_token = access_token;
			this.salt = salt;
			
		}
		
		public String getSalt() {
			return this.salt;
		}
		
		public OAuth2AccessToken getAccess_token() {
			return this.access_token;
		}
	}
	
}
