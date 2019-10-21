package com.ppublica.shopify.security.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.ppublica.shopify.security.service.EncryptedTokenAndSalt;


@Repository
public class ShopifyTokenRepositoryImpl implements TokenRepository {
	
	private static String SELECT_INFO_FOR_SHOP = "SELECT id, storeDomain, tokenType, tokenValue, salt, issuedAt, expiresAt, scopes FROM StoreAccessTokens WHERE storeDomain=?";
	private static final String SAVE_ACCESS_TOKEN = "INSERT INTO StoreAccessTokens(storeDomain,tokenType,tokenValue,salt,issuedAt,expiresAt,scopes) VALUES(?,?,?,?,?,?,?)";
	private static final String UPDATE_TOKEN_FOR_STORE = "UPDATE StoreAccessTokens SET tokenType=?, tokenValue=?, salt=?, issuedAt=?, expiresAt=?, scopes=? WHERE storeDomain=?";
	private static final String REMOVE_STORE = "DELETE FROM StoreAccessTokens WHERE storeDomain=?";
	private JdbcTemplate jdbc;
	
	@Autowired
	public void setJdbc(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	@Override
	public PersistedStoreAccessToken findTokenForStore(String store) {
		
		PersistedStoreAccessToken token = null;
		
		try {
			token = jdbc.queryForObject(SELECT_INFO_FOR_SHOP, new PersistedStoreAccessTokenMapper(), store);
		} catch(EmptyResultDataAccessException ex) {
			token = null;

		}

		return token;
	}
	
	static class PersistedStoreAccessTokenMapper implements RowMapper<PersistedStoreAccessToken> {

		@Override
		public PersistedStoreAccessToken mapRow(ResultSet rs, int arg) throws SQLException {
			Long id = rs.getLong("id");
			String storeDomain = rs.getString("storeDomain");
			String tokenType = rs.getString("tokenType");
			String tokenValue = rs.getString("tokenValue");
			String salt = rs.getString("salt");
			Long issuedAt = rs.getLong("issuedAt");
			Long expiresAt = rs.getLong("expiresAt");
			String scopesString = rs.getString("scopes");
			
			Set<String> scopes = Arrays.asList(scopesString.split(","))
										.stream()
											.map(i -> i.trim())
											.collect(Collectors.toSet());
			
			PersistedStoreAccessToken token = new PersistedStoreAccessToken();
			token.setId(id);
			token.setStoreDomain(storeDomain);
			token.setTokenType(tokenType);
			token.setIssuedAt(issuedAt);
			token.setExpiresAt(expiresAt);
			token.setScopes(scopes);
			token.setTokenAndSalt(new EncryptedTokenAndSalt(tokenValue, salt));
			
			return token;
			
		}
		
	}



	@Override
	public void saveNewStore(PersistedStoreAccessToken accessToken) {
		
		jdbc.update(SAVE_ACCESS_TOKEN, accessToken.getStoreDomain(), accessToken.getTokenType(), 
					accessToken.getTokenAndSalt().getEncryptedToken(), accessToken.getTokenAndSalt().getSalt(), 
					accessToken.getIssuedAt(), accessToken.getExpiresAt(), getScopeString(accessToken.getScopes()));

	}

	@Override
	public void updateStore(PersistedStoreAccessToken accessToken) {
		try {
			jdbc.update(UPDATE_TOKEN_FOR_STORE, accessToken.getTokenType(), 
				accessToken.getTokenAndSalt().getEncryptedToken(), accessToken.getTokenAndSalt().getSalt(), 
				accessToken.getIssuedAt(), accessToken.getExpiresAt(), getScopeString(accessToken.getScopes()),
				accessToken.getStoreDomain());	
		} catch(EmptyResultDataAccessException ex) {
			return;
		}
	}

	@Override
	public void uninstallStore(String storeName) {
		try {
			jdbc.update(REMOVE_STORE, storeName);
		} catch(EmptyResultDataAccessException ex) {
			return;
		}
	}
	
	private String getScopeString(Set<String> scopes) {
		return scopes.stream()
				.collect(Collectors.joining(","));
	}
	
	
}
