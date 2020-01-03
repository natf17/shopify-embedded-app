package com.ppublica.shopify.security.service;

/**
 * A container for an decrypted token and the salt used for encryption. The decrypted token is usually
 * used when saving or updating a store's credentials, or when making the raw token available to the 
 * ShopifyStore principal.
 * 
 * @author N F
 */
public class DecryptedTokenAndSalt {
	private final String decryptedToken;
	private final String salt;
	
	/**
	 * 
	 * @param decryptedToken The raw, decrypted token
	 * @param salt The salt used to encrypt the token
	 */
	public DecryptedTokenAndSalt(String decryptedToken, String salt) {
		this.decryptedToken = decryptedToken;
		this.salt = salt;

	}
	
	
	public String getDecryptedToken() {
		return this.decryptedToken;
	}
	
	public String getSalt() {
		return this.salt;
	}
	

}
