package com.ppublica.shopify.security.repository;


public class EncryptedTokenAndSalt {
	private final String encryptedToken;
	private final String salt;
	
	public EncryptedTokenAndSalt(String encyptedToken, String salt) {
		this.encryptedToken = encyptedToken;
		this.salt = salt;

	}
	
	
	public String getEncryptedToken() {
		return this.encryptedToken;
	}
	
	public String getSalt() {
		return this.salt;
	}
	
	
}
