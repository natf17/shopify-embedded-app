package com.ppublica.shopify.security.service;


public class EncryptedTokenAndSalt {
	private final String encryptedToken;
	private final String salt;
	
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
