package com.ppublica.shopify.security.web;

import static org.mockito.Mockito.mock;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

public class GenerateDefaultAuthorizationPageStrategyTests {
	GenerateDefaultAuthorizationPageStrategy strategy;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(GenerateDefaultAuthorizationPageStrategy.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() {
		Map<String, String> menuLinks = new LinkedHashMap<>();
		menuLinks.put("Products page", "/products");
		
		this.strategy = new GenerateDefaultAuthorizationPageStrategy(menuLinks);
	}
	
	// if request has query path, then match and print menu links
	@Test
	public void doFilterWhenHasQueryPathIsSubpathMatch() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication auth = mock(Authentication.class);
		
		strategy.handleAuthorizationPage(request, response, auth);
				
		String content = response.getContentAsString();

		// print menu links
		Assert.assertTrue(content.contains("Authentication/installation SUCCESS!"));
		Assert.assertTrue(content.contains("<a href=\"/products\">"));

		
	}

}
