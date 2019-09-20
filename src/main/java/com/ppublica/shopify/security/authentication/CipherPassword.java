package com.ppublica.shopify.security.authentication;

/*
 * This class holds a password loaded from a properties file for subsequent dynamic encryptor creation. 
 */
public class CipherPassword {
	private final String password;
	
	public CipherPassword(String password) {
		this.password = password;
	}
	
	public String getPassword() {
		return this.password;
	}
}
