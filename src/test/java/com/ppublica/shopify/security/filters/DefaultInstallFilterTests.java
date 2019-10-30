package com.ppublica.shopify.security.filters;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

public class DefaultInstallFilterTests {

	String pathToFilter = "/install";
	DefaultInstallFilter filter;
	
	@Before
	public void setup() {
		Map<String, String> menuLinks = new LinkedHashMap<>();
		menuLinks.put("Products page", "/products");
		
		this.filter = new DefaultInstallFilter(pathToFilter, menuLinks);
	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();

	}
	
	// if path doesn't match continue
	@Test
	public void doFilterWhenPathNoMatchThenContinue() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.setServletPath("/info/other");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		Authentication auth = mock(Authentication.class);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

	}
	
	// if path matches, and is not authenticated, print
	@Test
	public void doFilterWhenPathMatchAndNotAuthenticatedThenPrint() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install/shopify");
		request.setServletPath("/info/other");
		request.setAttribute(DefaultInstallFilter.PARENT_AUTHENTICATION_URI, "https://test-store/myshopify.com/admin");
		request.setAttribute(DefaultInstallFilter.I_FRAME_AUTHENTICATION_URI, "/oauth/authorize");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();
		
		Assert.assertTrue(content.contains("var redirectFromParentPath = 'https://test-store/myshopify.com/admin';"));
		Assert.assertTrue(content.contains("var redirectFromIFramePath = '/oauth/authorize';"));
		Assert.assertTrue(content.contains("There has been a problem logging in from the embedded app. Please log in directly from your browser."));
		

	}
	
	// if path matches and is authenticated, print menu links
	@Test
	public void doFilterWhenPathMatchAndAuthenticatedThenPrint() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install/shopify");
		request.setServletPath("/info/other");
		request.setAttribute(DefaultInstallFilter.PARENT_AUTHENTICATION_URI, "https://test-store/myshopify.com/admin");
		request.setAttribute(DefaultInstallFilter.I_FRAME_AUTHENTICATION_URI, "/oauth/authorize");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		OAuth2AuthenticationToken auth = mock(OAuth2AuthenticationToken.class);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();
		
		Assert.assertTrue(content.contains("var redirectFromParentPath = 'https://test-store/myshopify.com/admin';"));
		Assert.assertTrue(content.contains("var redirectFromIFramePath = '/oauth/authorize';"));
		Assert.assertTrue(content.contains("WELCOME"));

		// print menu links
		Assert.assertTrue(content.contains("<a href=\"/products\">"));

		
	}
	
}
