package com.ppublica.shopify.security.service;

/**
 * A container for an encrypted token and the salt used for encryption. The encrypted token is usually
 * as it exists in the database.
 * 
 * @author N F
 *
 */
public class EncryptedTokenAndSalt {
	private final String encryptedToken;
	private final String salt;
	
	/**
	 * 
	 * @param encryptedToken The encrypted token
	 * @param salt The salt used to encrypt the token
	 */
	public EncryptedTokenAndSalt(String encryptedToken, String salt) {
		this.encryptedToken = encryptedToken;
		this.salt = salt;

	}
	
	
	public String getEncryptedToken() {
		return this.encryptedToken;
	}
	
	public String getSalt() {
		return this.salt;
	}
	
	
}
