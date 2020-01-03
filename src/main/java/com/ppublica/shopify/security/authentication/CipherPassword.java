package com.ppublica.shopify.security.authentication;


/**
 * Holds a password loaded from a properties file for subsequent dynamic encryptor creation.
 * 
 * @author N F
 *
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
