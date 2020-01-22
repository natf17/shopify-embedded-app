package com.ppublica.shopify.security.web;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

import java.util.Arrays;
import java.util.HashSet;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;


public class ShopifyRedirectStrategyTests {
	
	OAuth2AuthorizationRequest authorizationRequest;

	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyRedirectStrategy.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() {
		authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId("client-id")
				.authorizationUri("https://testStore.myshopify.com/admin/oauth/authorize")
				.redirectUri("https://ppublica.com/login/app/oauth2/code/shopify")
				.scopes(new HashSet<>(Arrays.asList("read_products", "write_products")))
				.state("statekey")
				.build();
	}

	@Test
	public void saveRedirectAuthenticationUrisWhenCorrectThenSaveInRequest() {
		
		ShopifyRedirectStrategy srs = new ShopifyRedirectStrategy();
	
		HttpServletRequest req = mock(HttpServletRequest.class);

		srs.saveRedirectAuthenticationUris(req, authorizationRequest);

		verify(req, times(1)).setAttribute("PARENT_AUTHENTICATION_URI", "https://testStore.myshopify.com/admin/oauth/authorize?client_id=client-id&redirect_uri=https://ppublica.com/login/app/oauth2/code/shopify&scope=read_products,write_products&state=statekey");
		verify(req, times(1)).setAttribute("I_FRAME_AUTHENTICATION_URI", "/oauth/authorize?client_id=client-id&redirect_uri=https://ppublica.com/login/app/oauth2/code/shopify&scope=read_products,write_products&state=statekey");
		
		
	}
	
	@Test
	public void concatenateListIntoCommaStringWhenCorrectThenReturnString() {
		
		String scopes = "read,write,update,share";
		
		String result = ShopifyRedirectStrategy.concatenateListIntoCommaString(Arrays.asList(scopes.split(",")));
		
		Assert.assertEquals("read,write,update,share", result);
	}
	
	@Test
	public void concatenateListIntoCommaStringWhenEndingInCommaThenReturnString() {
		
		String scopes = "read,write,update,share,";
		
		String result = ShopifyRedirectStrategy.concatenateListIntoCommaString(Arrays.asList(scopes.split(",")));
		
		Assert.assertEquals("read,write,update,share", result);
	}
}
