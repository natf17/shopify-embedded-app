
package com.ppublica.shopify.security.filters;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

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
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

public class DefaultLoginEndpointFilterTests {
	String loginEndpoint = "/init";
	String installPath = "/install";
	String logoutEndpoint = "/logout";
	
	DefaultLoginEndpointFilter filter;
	
	@Before
	public void setup() {
		this.filter = new DefaultLoginEndpointFilter(loginEndpoint, installPath, logoutEndpoint);
	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();

	}
	
	// if path doesn't match continue
	@Test
	public void doFilterWhenPathNoMatchThenContinue() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/info");
		request.setServletPath("/info");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		Authentication auth = mock(Authentication.class);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

	}
	
	// if path matches, and is not authenticated, print form
	@Test
	public void doFilterWhenPathMatchAndNotAuthenticatedThenPrint() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/init");
		request.setServletPath("/init");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		SecurityContextHolder.getContext().setAuthentication(null);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();

		Assert.assertTrue(content.contains("<form method=\"GET\" action=\"/install/shopify\""));

	}
	
	// if path matches and is authenticated, print logout with csrf
	@Test
	public void doFilterWhenPathMatchAndsAuthenticatedThenPrint() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/init");
		request.setServletPath("/init");
		request.setAttribute(CsrfToken.class.getName(), new DefaultCsrfToken("header-name", "param-name", "csrf-token"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		OAuth2AuthenticationToken auth = mock(OAuth2AuthenticationToken.class);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();
		
		Assert.assertTrue(content.contains("You are already logged in."));
		Assert.assertTrue(content.contains("<form method=\"POST\" action=\"/logout\""));
		Assert.assertTrue(content.contains("<input type=\"hidden\" name=\"param-name\" value=\"csrf-token\">"));
		
	}
	

}
