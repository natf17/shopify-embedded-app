package com.ppublica.shopify.security.repository;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import com.ppublica.shopify.TestDataSource;
import com.ppublica.shopify.security.service.EncryptedTokenAndSalt;

public class ShopifyTokenRepositoryImplTests {
	
	ShopifyTokenRepositoryImpl repo;
	TestDataSource dataSource;
	JdbcTemplate template;
	EncryptedTokenAndSalt tS;
	String accessToken = "access-token";
	String salt = "salt";
	String shop = "lmdev.myshopify.com";
	String scope = "read_products,write_products";
	
	@Before
	public void setup() {
		dataSource = new TestDataSource("shopifysecuritytest");
		template = new JdbcTemplate(dataSource);
		
		template.execute("CREATE TABLE STOREACCESSTOKENS(id BIGINT NOT NULL IDENTITY, storeDomain VARCHAR(50) NOT NULL, tokenType VARCHAR(50) NOT NULL, tokenValue VARCHAR(100) NOT NULL, salt VARCHAR(100) NOT NULL, issuedAt BIGINT NOT NULL, expiresAt BIGINT NOT NULL, scopes VARCHAR(200) NOT NULL);");
		template.execute("INSERT INTO STOREACCESSTOKENS(storeDomain,tokenType,tokenValue,salt,issuedAt,expiresAt,scopes) VALUES('lmdev.myshopify.com','BEARER','token-value','salt-value',2000,3000,'read_products,write_products');");
		
		repo = new ShopifyTokenRepositoryImpl();
		repo.setJdbc(template);
		
		tS = new EncryptedTokenAndSalt("token", "salt");
		
	}
	
	@After
	public void cleanup() {
		dataSource.destroy();
	}
	
	@Test
	public void findTokenForStoreWhenExistsReturnsOAuth2AccessTokenWithSalt() {
		PersistedStoreAccessToken token = repo.findTokenForStore("lmdev.myshopify.com");
		Assert.assertNotNull(token);
		Assert.assertEquals("lmdev.myshopify.com", token.getStoreDomain());
		Assert.assertEquals("BEARER", token.getTokenType());
		Assert.assertEquals("token-value", token.getTokenAndSalt().getEncryptedToken());
		Assert.assertEquals("salt-value", token.getTokenAndSalt().getSalt());
		Assert.assertEquals(new Long(2000), token.getIssuedAt());
		Assert.assertEquals(new Long(3000), token.getExpiresAt());

		Assert.assertEquals(2, token.getScopes().size());
		Assert.assertTrue(token.getScopes().contains("read_products"));
		Assert.assertTrue(token.getScopes().contains("write_products"));
		
	}
	
	@Test
	public void findTokenForRequestWhenDoesntExistReturnsNull() {
		Assert.assertNull(repo.findTokenForStore("other.myshopify.com"));
	}

	
	@Test
	public void saveNewStoreSavesStore() {
		String storeDomain = "new-store";
		String tokenType = "BEARER";
		String tokenValue = "new-token";
		String salt = "new-salt";
		Long issuedAt = new Long(1000);
		Long expiresAt = new Long(9800);
		Set<String> scopes = new HashSet<>(Arrays.asList("read", "write"));

		
		PersistedStoreAccessToken token = new PersistedStoreAccessToken();
		token.setStoreDomain(storeDomain);
		token.setTokenType(tokenType);
		token.setIssuedAt(issuedAt);
		token.setExpiresAt(expiresAt);
		token.setScopes(scopes);
		token.setTokenAndSalt(new EncryptedTokenAndSalt(tokenValue, salt));
		
		
		repo.saveNewStore(token);
		PersistedStoreAccessToken result = template.queryForObject("SELECT id, storeDomain, tokenType, tokenValue, salt, issuedAt, expiresAt, scopes FROM StoreAccessTokens WHERE storeDomain=?", new ShopifyTokenRepositoryImpl.PersistedStoreAccessTokenMapper(), "new-store");

		Assert.assertNotNull(result);
		Assert.assertEquals("new-store", result.getStoreDomain());
		Assert.assertEquals("BEARER", result.getTokenType());
		Assert.assertEquals("new-token", result.getTokenAndSalt().getEncryptedToken());
		Assert.assertEquals("new-salt", result.getTokenAndSalt().getSalt());
		Assert.assertEquals(new Long(1000), result.getIssuedAt());
		Assert.assertEquals(new Long(9800), result.getExpiresAt());

		Assert.assertEquals(2, result.getScopes().size());
		Assert.assertTrue(result.getScopes().contains("read"));
		Assert.assertTrue(result.getScopes().contains("write"));
		
	}
	
	@Test
	public void updateStoreDoesUpdateStore() {
		String tokenType = "BEARER";
		String tokenValue = "new-token";
		String salt = "new-salt";
		Long issuedAt = new Long(1000);
		Long expiresAt = new Long(9800);
		Set<String> scopes = new HashSet<>(Arrays.asList("read", "write"));

		
		PersistedStoreAccessToken token = new PersistedStoreAccessToken();
		token.setStoreDomain(shop);
		token.setTokenType(tokenType);
		token.setIssuedAt(issuedAt);
		token.setExpiresAt(expiresAt);
		token.setScopes(scopes);
		token.setTokenAndSalt(new EncryptedTokenAndSalt(tokenValue, salt));
		
		
		
		repo.updateStore(token);
		
		PersistedStoreAccessToken result = template.queryForObject("SELECT id, storeDomain, tokenType, tokenValue, salt, issuedAt, expiresAt, scopes FROM StoreAccessTokens WHERE storeDomain=?", new ShopifyTokenRepositoryImpl.PersistedStoreAccessTokenMapper(), shop);

		Assert.assertNotNull(result);
		
		// assert that properties were updated for the store
		Assert.assertEquals("BEARER", result.getTokenType());
		Assert.assertEquals("new-token", result.getTokenAndSalt().getEncryptedToken());
		Assert.assertEquals("new-salt", result.getTokenAndSalt().getSalt());
		Assert.assertEquals(new Long(1000), result.getIssuedAt());
		Assert.assertEquals(new Long(9800), result.getExpiresAt());

		Assert.assertEquals(2, result.getScopes().size());
		Assert.assertTrue(result.getScopes().contains("read"));
		Assert.assertTrue(result.getScopes().contains("write"));
		
		// everything else should have stayed the same
		Assert.assertEquals(shop, result.getStoreDomain());

		
	}
	
	@Test(expected=EmptyResultDataAccessException.class)
	public void updateKeyWhenDoesntExistDoesNothing() {
		String tokenType = "BEARER";
		String tokenValue = "new-token";
		String salt = "new-salt";
		Long issuedAt = new Long(1000);
		Long expiresAt = new Long(9800);
		Set<String> scopes = new HashSet<>(Arrays.asList("read", "write"));

		
		PersistedStoreAccessToken token = new PersistedStoreAccessToken();
		token.setStoreDomain("non-existing-store");
		token.setTokenType(tokenType);
		token.setIssuedAt(issuedAt);
		token.setExpiresAt(expiresAt);
		token.setScopes(scopes);
		token.setTokenAndSalt(new EncryptedTokenAndSalt(tokenValue, salt));
		
		
		repo.updateStore(token);
		
		template.queryForObject("SELECT id, storeDomain, tokenType, tokenValue, salt, issuedAt, expiresAt, scopes FROM StoreAccessTokens WHERE storeDomain=?", new ShopifyTokenRepositoryImpl.PersistedStoreAccessTokenMapper(), "non-existing-store");
		
	}
	
	
	@Test(expected=EmptyResultDataAccessException.class)
	public void uninstallStoreRemovesStore() {
		repo.uninstallStore(shop);
		
		template.queryForObject("SELECT id, storeDomain, tokenType, tokenValue, salt, issuedAt, expiresAt, scopes FROM StoreAccessTokens WHERE storeDomain=?", new ShopifyTokenRepositoryImpl.PersistedStoreAccessTokenMapper(), "non-existing-store");
		
	}
	
}
