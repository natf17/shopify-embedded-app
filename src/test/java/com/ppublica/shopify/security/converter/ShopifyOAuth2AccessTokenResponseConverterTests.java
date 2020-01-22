package com.ppublica.shopify.security.converter;

import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

public class ShopifyOAuth2AccessTokenResponseConverterTests {
	
	ShopifyOAuth2AccessTokenResponseConverter converter;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyOAuth2AccessTokenResponseConverter.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() {
		this.converter = new ShopifyOAuth2AccessTokenResponseConverter();
	}
	
	@Test
	public void convertGivenShopifyParametersConstructsOAuth2AccessTokenResponse() {
		Map<String, String> tokenResponseParameters = new HashMap<>();
		
		tokenResponseParameters.put("access_token", "raw-token");
		tokenResponseParameters.put("scope", "write_orders,read_customers");
		tokenResponseParameters.put("other", "other-param-value");
		
		
		OAuth2AccessTokenResponse resp = converter.convert(tokenResponseParameters);
		
		OAuth2AccessToken token = resp.getAccessToken();
		Map<String,Object> additionalParams = resp.getAdditionalParameters();
		
		Assert.assertNotNull(token.getExpiresAt());
		Assert.assertNotNull(token.getIssuedAt());
		Assert.assertEquals(token.getIssuedAt().truncatedTo(ChronoUnit.SECONDS), token.getExpiresAt().truncatedTo(ChronoUnit.SECONDS).minusSeconds(31536000L));
		Assert.assertTrue(token.getScopes().contains("write_orders"));
		Assert.assertTrue(token.getScopes().contains("read_customers"));
		Assert.assertEquals(OAuth2AccessToken.TokenType.BEARER, token.getTokenType());
		Assert.assertEquals("raw-token", token.getTokenValue());

		Assert.assertEquals("other-param-value", additionalParams.get("other"));

		
	}
}
