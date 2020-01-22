package com.ppublica.shopify.security.filters;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import com.ppublica.shopify.security.service.ShopifyStore;

public class DefaultUserInfoFilterTests {
	
	String pathToFilter = "/info";
	DefaultUserInfoFilter filter;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(DefaultUserInfoFilter.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() {
		this.filter = new DefaultUserInfoFilter(pathToFilter);
	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();

	}
	
	// if path doesn't match continue
	@Test
	public void doFilterWhenPathNoMatchThenContinue() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/info/other");
		request.setServletPath("/info/other");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		Authentication auth = mock(Authentication.class);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

	}
	
	// if path matches, but is not authenticated, continue
	@Test
	public void doFilterWhenPathMatchButNotAuthenticatedThenContinue() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/info/other");
		request.setServletPath("/info/other");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

	}
	
	// if path matches and is authenticated, print page with correct values - from embedded
	@Test
	public void doFilterWhenPathMatchAndAuthenticatedThenPrintPageEmbedded() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/info");
		request.setServletPath("/info");
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpSession mockSession = mock(HttpSession.class);
		when(mockSession.getAttribute("SHOPIFY_EMBEDDED_APP")).thenReturn(true);
		request.setSession(mockSession);
		
		
		OAuth2AuthenticationToken auth = mock(OAuth2AuthenticationToken.class);
		ShopifyStore store = new ShopifyStore("store-domain", "access-token", "api-key", null);
		when(auth.getPrincipal()).thenReturn(store);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();
		
		Assert.assertTrue(content.contains("store-domain"));
		Assert.assertTrue(content.contains("api-key"));
		Assert.assertTrue(content.contains("true"));
		
	}
	
	// if path matches and is authenticated, print page with correct values - not from embedded
	@Test
	public void doFilterWhenPathMatchAndAuthenticatedThenPrintPageBrowser() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/info");
		request.setServletPath("/info");
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpSession mockSession = mock(HttpSession.class);
		when(mockSession.getAttribute("SHOPIFY_EMBEDDED_APP")).thenReturn(null);
		request.setSession(mockSession);
			
		
		OAuth2AuthenticationToken auth = mock(OAuth2AuthenticationToken.class);
		ShopifyStore store = new ShopifyStore("store-domain", "access-token", "api-key", null);
		when(auth.getPrincipal()).thenReturn(store);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();
		
		Assert.assertTrue(content.contains("store-domain"));
		Assert.assertTrue(content.contains("api-key"));
		Assert.assertTrue(content.contains("false"));
		
	}
	
	
	
}
