package com.ppublica.shopify.security.repository;

import java.util.Set;

import com.ppublica.shopify.security.service.EncryptedTokenAndSalt;

/**
 * A representation of a row in the database that stores Shopify-administered OAuth tokens.
 * @author N F
 * @see ShopifyTokenRepositoryImpl
 */
public class PersistedStoreAccessToken {
	private Long id;
	private EncryptedTokenAndSalt tokenAndSalt;
	private String storeDomain;
	private String tokenType;
	private Long issuedAt;
	private Long expiresAt;
	private Set<String> scopes;
	
	public void setId(Long id) {
		this.id = id;
	}
	
	public Long getId() {
		return this.id;
	}
	
	public void setTokenAndSalt(EncryptedTokenAndSalt tokenAndSalt) {
		this.tokenAndSalt = tokenAndSalt;
	}
	
	public EncryptedTokenAndSalt getTokenAndSalt() {
		return this.tokenAndSalt;
	}
	
	public void setStoreDomain(String storeDomain) {
		this.storeDomain = storeDomain;
	}
	
	public String getStoreDomain() {
		return this.storeDomain;
	}
	
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	
	public String getTokenType() {
		return this.tokenType;
	}
	
	public void setIssuedAt(Long issuedAt) {
		this.issuedAt = issuedAt;
	}
	
	public Long getIssuedAt() {
		return this.issuedAt;
	}
	
	public void setExpiresAt(Long expiresAt) {
		this.expiresAt = expiresAt;
	}
	
	public Long getExpiresAt() {
		return this.expiresAt;
	}
	
	public void setScopes(Set<String> scopes) {
		this.scopes = scopes;
	}
	
	public Set<String> getScopes() {
		return this.scopes;
	}

}
