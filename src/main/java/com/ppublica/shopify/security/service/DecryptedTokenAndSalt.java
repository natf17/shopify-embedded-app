package com.ppublica.shopify.security.service;

public class DecryptedTokenAndSalt {
	private final String decryptedToken;
	private final String salt;
	
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
