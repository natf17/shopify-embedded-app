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

public class DefaultAuthorizationRedirectPathFilterTests {

	String pathToFilter = "/login/app/oauth2/code";
	DefaultAuthorizationRedirectPathFilter filter;
	
	@Before
	public void setup() {
		Map<String, String> menuLinks = new LinkedHashMap<>();
		menuLinks.put("Products page", "/products");
		
		this.filter = new DefaultAuthorizationRedirectPathFilter(pathToFilter, menuLinks);
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
	
	// if path matches exactly, then print
	@Test
	public void doFilterWhenPathExactlyThenPrint() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/app/oauth2/code");
		request.setServletPath("/login/app/oauth2/code");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();

		// print menu links
		Assert.assertTrue(content.contains("Authentication/installation SUCCESS!"));
		Assert.assertTrue(content.contains("<a href=\"/products\">"));

	}
	
	// if request is to subpath, then match and print menu links
	@Test
	public void doFilterWhenPathIsSubpathMatch() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/app/oauth2/code/sub");
		request.setServletPath("/login/app/oauth2/code/sub");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();

		// print menu links
		Assert.assertTrue(content.contains("Authentication/installation SUCCESS!"));
		Assert.assertTrue(content.contains("<a href=\"/products\">"));

		
	}
	
	// if request has query path, then match and print menu links
	@Test
	public void doFilterWhenHasQueryPathIsSubpathMatch() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/app/oauth2/code/sub?shop=sd");
		request.setQueryString("shop=sd");
		request.setServletPath("/login/app/oauth2/code/sub");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();

		// print menu links
		Assert.assertTrue(content.contains("Authentication/installation SUCCESS!"));
		Assert.assertTrue(content.contains("<a href=\"/products\">"));

		
	}
	
}
