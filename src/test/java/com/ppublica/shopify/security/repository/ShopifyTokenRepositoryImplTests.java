package com.ppublica.shopify.security.repository;

import java.util.Arrays;
import java.util.HashSet;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import com.ppublica.shopify.TestDataSource;
import com.ppublica.shopify.security.repository.TokenRepository.OAuth2AccessTokenWithSalt;

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
		
		template.execute("CREATE TABLE STOREACCESSTOKENS(id BIGINT NOT NULL IDENTITY, shop VARCHAR(50) NOT NULL, access_token VARCHAR(100) NOT NULL, salt VARCHAR(100) NOT NULL, scope VARCHAR(200) NOT NULL);");
		template.execute("INSERT INTO STOREACCESSTOKENS(shop,access_token,salt,scope) VALUES('lmdev.myshopify.com','access-token','salt','read_products,write_products');");
		
		repo = new ShopifyTokenRepositoryImpl();
		repo.setJdbc(template);
		
		tS = new EncryptedTokenAndSalt("token", "salt");
		
	}
	
	@After
	public void cleanup() {
		dataSource.destroy();
	}
	
	@Test
	public void findTokenForRequestWhenExistsReturnsOAuth2AccessTokenWithSalt() {
		OAuth2AccessTokenWithSalt token = repo.findTokenForRequest("lmdev.myshopify.com");
		Assert.assertNotNull(token);
		Assert.assertEquals("salt", token.getSalt());
		Assert.assertEquals("access-token", token.getAccess_token().getTokenValue());
		Assert.assertEquals(2, token.getAccess_token().getScopes().size());
		Assert.assertTrue(token.getAccess_token().getScopes().contains("read_products"));
		Assert.assertTrue(token.getAccess_token().getScopes().contains("write_products"));
		
	}
	
	@Test
	public void findTokenForRequestWhenDoesntExistReturnsNull() {
		Assert.assertNull(repo.findTokenForRequest("other.myshopify.com"));
	}

	
	@Test
	public void saveNewStoreSavesStore() {
		
		repo.saveNewStore("new-store", new HashSet<>(Arrays.asList("read", "write")), new EncryptedTokenAndSalt("new-token", "new-salt"));
		OAuth2AccessTokenWithSalt token = template.queryForObject("SELECT access_token, salt, scope FROM StoreAccessTokens WHERE shop=?", new ShopifyTokenRepositoryImpl.StoreTokensMapper(), "new-store");

		Assert.assertNotNull(token);
		Assert.assertEquals("new-salt", token.getSalt());
		Assert.assertEquals("new-token", token.getAccess_token().getTokenValue());
		Assert.assertEquals(2, token.getAccess_token().getScopes().size());
		Assert.assertTrue(token.getAccess_token().getScopes().contains("read"));
		Assert.assertTrue(token.getAccess_token().getScopes().contains("write"));
		
	}
	
	@Test
	public void updateKeyUpdatesStore() {
		repo.updateKey(shop, new EncryptedTokenAndSalt("new-token", "new-salt"));
		OAuth2AccessTokenWithSalt token = template.queryForObject("SELECT access_token, salt, scope FROM StoreAccessTokens WHERE shop=?", new ShopifyTokenRepositoryImpl.StoreTokensMapper(), shop);

		Assert.assertNotNull(token);
		
		// assert that the credentials were updated for the store
		Assert.assertEquals("new-salt", token.getSalt());
		Assert.assertEquals("new-token", token.getAccess_token().getTokenValue());
		
		// everything else should have stayed the same
		Assert.assertEquals(2, token.getAccess_token().getScopes().size());
		Assert.assertTrue(token.getAccess_token().getScopes().contains("read_products"));
		Assert.assertTrue(token.getAccess_token().getScopes().contains("write_products"));
		
	}
	
	@Test
	public void updateKeyWhenDoesntExistDoesNothing() {
		repo.updateKey("other-store", new EncryptedTokenAndSalt("new-token", "new-salt"));
		OAuth2AccessTokenWithSalt token = template.queryForObject("SELECT access_token, salt, scope FROM StoreAccessTokens WHERE shop=?", new ShopifyTokenRepositoryImpl.StoreTokensMapper(), shop);

		Assert.assertNotNull(token);
		
	}
	
	@Test(expected=EmptyResultDataAccessException.class)
	public void uninstallStoreRemovesStore() {
		repo.uninstallStore(shop);
		
		template.queryForObject("SELECT access_token, salt, scope FROM StoreAccessTokens WHERE shop=?", new ShopifyTokenRepositoryImpl.StoreTokensMapper(), shop);
		
	}
	
}
