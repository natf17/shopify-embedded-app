package com.ppublica.shopify.security.filters;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

public class DefaultAuthenticationFailureFilterTests {

	String pathToFilter = "/auth/error";
	DefaultAuthenticationFailureFilter filter;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(DefaultAuthenticationFailureFilter.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() {
		this.filter = new DefaultAuthenticationFailureFilter(pathToFilter);
	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();

	}
	
	// if path doesn't match continue
	@Test
	public void doFilterWhenPathNoMatchThenContinue() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.setServletPath("/install");
		MockHttpServletResponse response = new MockHttpServletResponse();
	
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

	}
	
	// if path matches exactly, then print
	@Test
	public void doFilterWhenPathExactlyThenPrint() throws Exception {		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/auth/error");
		request.setServletPath("/auth/error");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		String content = response.getContentAsString();

		Assert.assertTrue(content.contains("An error occurred during authentication"));

	}
	
}
