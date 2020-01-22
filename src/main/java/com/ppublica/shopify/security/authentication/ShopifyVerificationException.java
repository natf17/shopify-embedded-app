package com.ppublica.shopify.security.authentication;

public class ShopifyVerificationException extends RuntimeException {

	private static final long serialVersionUID = 615605856447976486L;
	
	/**
	 * Constructs a ShopifyVerificationException with the specified message and root
	 * cause.
	 *
	 * @param msg the detail message
	 * @param t the root cause
	 */
	public ShopifyVerificationException(String msg, Throwable t) {
		super(msg, t);
	}

	/**
	 * Constructs a ShopifyVerificationException with the specified message and no
	 * root cause.
	 *
	 * @param msg the detail message
	 */
	public ShopifyVerificationException(String msg) {
		super(msg);
	}

}
