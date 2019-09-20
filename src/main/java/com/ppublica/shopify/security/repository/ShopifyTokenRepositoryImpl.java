package com.ppublica.shopify.security.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.joining;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Repository;


@Repository
public class ShopifyTokenRepositoryImpl implements TokenRepository {
	
	private static String SELECT_INFO_FOR_SHOP = "SELECT access_token, salt, scope FROM StoreAccessTokens WHERE shop=?";
	private static final String SAVE_ACCESS_TOKEN_CREDENTIALS = "INSERT INTO StoreAccessTokens(shop,access_token,salt,scope) VALUES(?,?,?,?)";
	private static final String UPDATE_TOKEN_FOR_SHOP = "UPDATE StoreAccessTokens SET access_token=?, salt=? WHERE shop=?";
	private static final String REMOVE_SHOP = "DELETE FROM StoreAccessTokens WHERE shop=?";
	private JdbcTemplate jdbc;
	
	@Autowired
	public void setJdbc(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	@Override
	public OAuth2AccessTokenWithSalt findTokenForRequest(String shop) {
		
		OAuth2AccessTokenWithSalt token = null;
		
		try {
			token = jdbc.queryForObject(SELECT_INFO_FOR_SHOP, new StoreTokensMapper(), shop);
		} catch(EmptyResultDataAccessException ex) {
			token = null;

		}

		return token;
	}
	
	class StoreTokensMapper implements RowMapper<OAuth2AccessTokenWithSalt> {

		@Override
		public OAuth2AccessTokenWithSalt mapRow(ResultSet rs, int arg) throws SQLException {
			String encryptedToken = rs.getString("access_token");
			String salt = rs.getString("salt");
			String scope = rs.getString("scope");
			
			Set<String> scopes = Arrays.asList(scope.split(",")).stream().collect(Collectors.toSet());
			
			OAuth2AccessToken access_Token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, encryptedToken, null, null, scopes);
			
			return new OAuth2AccessTokenWithSalt(access_Token, salt);
			
		}
		
	}



	@Override
	public void saveNewStore(String shop, Set<String> scopes, EncryptedTokenAndSalt encryptedTokenAndSalt) {
		String scopeString = scopes.stream()
										.collect(joining(","));
		
		jdbc.update(SAVE_ACCESS_TOKEN_CREDENTIALS, shop, encryptedTokenAndSalt.getEncryptedToken(), encryptedTokenAndSalt.getSalt(), scopeString);

	}

	@Override
	public void updateKey(String shop, EncryptedTokenAndSalt encryptedTokenAndSalt) {
		jdbc.update(UPDATE_TOKEN_FOR_SHOP, encryptedTokenAndSalt.getEncryptedToken(), encryptedTokenAndSalt.getSalt(), shop);		
	}

	@Override
	public void uninstallStore(String storeName) {
		jdbc.update(REMOVE_SHOP, storeName);
	}
	
	
}
