package com.ppublica.shopify.security.web;

import static org.mockito.Mockito.mock;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

public class SaveAuthenticationSessionAuthenticationStrategyTests {
	
	SaveAuthenticationSessionAuthenticationStrategy strategy = new SaveAuthenticationSessionAuthenticationStrategy();
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}
	
	@Test
	public void onAuthenticationSavesAuthentication() {
		strategy.onAuthentication(mock(OAuth2AuthenticationToken.class), new MockHttpServletRequest(), new MockHttpServletResponse());
		
		Assert.assertTrue(SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2AuthenticationToken);
	}
	

}
