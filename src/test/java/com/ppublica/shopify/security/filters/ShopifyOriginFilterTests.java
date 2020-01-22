package com.ppublica.shopify.security.filters;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import com.ppublica.shopify.security.authentication.ShopifyOriginToken;
import com.ppublica.shopify.security.authentication.ShopifyVerificationStrategy;

public class ShopifyOriginFilterTests {
	ShopifyVerificationStrategy verificationStrategy;
	String authorizationPath;
	String restrictedPath;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyOriginFilter.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() {
		verificationStrategy = mock(ShopifyVerificationStrategy.class);
		authorizationPath = "/login/app/oauth2/code/**";
		restrictedPath = "/install/**";

	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();

	}
	
	@Test
	public void doFilterWhenUriNotMatchThenNextFilter() throws Exception {
		
		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/other/path");
		request.setServletPath("/other/path");
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(verificationStrategy, never()).isShopifyRequest(any());
		verify(verificationStrategy, never()).hasValidNonce(any());
		
	}
	
	// if it's any of the paths the verificationstrategy is called
	@Test
	public void doFilterWhenUriMatchThenCallVerificationStrategy() throws Exception {
		
		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/install/shopify");
		request.setServletPath("/install/shopify");
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
	
	}
	
	// if it must be from Shopify it must check for a nonce
	@Test
	public void doFilterWhenAuthorizationUriThenCheckNonce() throws Exception {
		doReturn(true).when(verificationStrategy).isShopifyRequest(any());
		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/app/oauth2/code/");
		request.setServletPath("/login/app/oauth2/code/");
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, times(1)).hasValidNonce(any());
	
	}
	
	// if it must be from shopify and it isn't call accessdenied handler and dont call next filter
	@Test
	public void doFilterWhenAuthorizationUriNotFromShopifyThenStop() throws Exception {
		doReturn(false).when(verificationStrategy).isShopifyRequest(any());
		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/app/oauth2/code/");
		request.setServletPath("/login/app/oauth2/code/");
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(chain, never()).doFilter(any(), any());
		Assert.assertEquals(403, response.getStatus());
		
	}
	
	// if it must be from shopify and it is but it has an invalid nonce then call accessdenied handler and dont call next filter
	@Test
	public void doFilterWhenAuthorizationUriFromShopifyInvalidNonceThenStop() throws Exception {
		doReturn(true).when(verificationStrategy).isShopifyRequest(any());
		doReturn(false).when(verificationStrategy).hasValidNonce(any());

		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/app/oauth2/code/");
		request.setServletPath("/login/app/oauth2/code/");
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, times(1)).hasValidNonce(any());
		verify(chain, never()).doFilter(any(), any());
		Assert.assertEquals(403, response.getStatus());

		
	}
	// if it must be from shopify and it is and has valid nonce then continue
	@Test
	public void doFilterWhenAuthorizationUriFromShopifyAndValidNonceThenContinue() throws Exception {
		doReturn(true).when(verificationStrategy).isShopifyRequest(any());
		doReturn(true).when(verificationStrategy).hasValidNonce(any());

		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/app/oauth2/code/");
		request.setServletPath("/login/app/oauth2/code/");
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, times(1)).hasValidNonce(any());
		verify(chain, times(1)).doFilter(any(), any());;
		
	}
	
	@Test
	public void doFilterWhenMaybeUriNotFromShopifyAndNotAuthenticatedAndHasEmbeddedAppAttrThenContinueAndRemoveEmbeddedAppAttr() throws Exception {
		doReturn(false).when(verificationStrategy).isShopifyRequest(any());

		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.setServletPath("/install/");
		request.getSession().setAttribute("SHOPIFY_EMBEDDED_APP", true);
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, never()).hasValidNonce(any());
		verify(chain, times(1)).doFilter(any(), any());
		
		Assert.assertNull(request.getSession().getAttribute("SHOPIFY_EMBEDDED_APP"));
		Assert.assertNull(SecurityContextHolder.getContext().getAuthentication());

	}
	
	@Test
	public void doFilterWhenMaybeUriNotFromShopifyAndAuthenticatedAndHasEmbeddedAppAttrThenContinueAndKeepEmbeddedAppAttr() throws Exception {
		doReturn(false).when(verificationStrategy).isShopifyRequest(any());

		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.setServletPath("/install/");
		request.getSession().setAttribute("SHOPIFY_EMBEDDED_APP", true);
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		OAuth2AuthenticationToken auth = mock(OAuth2AuthenticationToken.class);
		SecurityContextHolder.getContext().setAuthentication(auth);

		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, never()).hasValidNonce(any());
		verify(chain, times(1)).doFilter(any(), any());
		
		Assert.assertTrue((boolean)request.getSession().getAttribute("SHOPIFY_EMBEDDED_APP"));
		Assert.assertEquals(auth, SecurityContextHolder.getContext().getAuthentication());


	}
	
	@Test
	public void doFilterWhenMaybeUriNotFromShopifyAndAuthenticatedAndHasNoEmbeddedAppAttrThenContinueAndDontAddEmbeddedAppAttr() throws Exception {
		doReturn(false).when(verificationStrategy).isShopifyRequest(any());

		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.getSession();
		request.setServletPath("/install/");
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthenticationToken auth = mock(OAuth2AuthenticationToken.class);
		SecurityContextHolder.getContext().setAuthentication(auth);

		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, never()).hasValidNonce(any());
		verify(chain, times(1)).doFilter(any(), any());
		
		Assert.assertNull(request.getSession().getAttribute("SHOPIFY_EMBEDDED_APP"));
		Assert.assertEquals(auth, SecurityContextHolder.getContext().getAuthentication());


	}
	
	@Test
	public void doFilterWhenMaybeUriIsFromShopifyAndNotAuthenticatedThenContinueAndSetEmbeddedAppAttrAndSetAuth() throws Exception {
		doReturn(true).when(verificationStrategy).isShopifyRequest(any());

		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.getSession();
		request.setServletPath("/install/");
		MockHttpServletResponse response = new MockHttpServletResponse();


		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, never()).hasValidNonce(any());
		verify(chain, times(1)).doFilter(any(), any());
		
		Assert.assertTrue((boolean)request.getSession().getAttribute("SHOPIFY_EMBEDDED_APP"));
		Assert.assertTrue(SecurityContextHolder.getContext().getAuthentication().getClass().isAssignableFrom(ShopifyOriginToken.class));
		
	}
	
	@Test
	public void doFilterWhenMaybeUriIsFromShopifyAndAuthenticatedThenContinueAndSetEmbeddedAppAttrAndDontSetAuth() throws Exception {
		doReturn(true).when(verificationStrategy).isShopifyRequest(any());

		ShopifyOriginFilter filter = new ShopifyOriginFilter(verificationStrategy, authorizationPath, restrictedPath);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.getSession();
		request.setServletPath("/install/");
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthenticationToken auth = mock(OAuth2AuthenticationToken.class);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(verificationStrategy, times(1)).isShopifyRequest(any());
		verify(verificationStrategy, never()).hasValidNonce(any());
		verify(chain, times(1)).doFilter(any(), any());
		
		Assert.assertTrue((boolean)request.getSession().getAttribute("SHOPIFY_EMBEDDED_APP"));
		Assert.assertEquals(auth, SecurityContextHolder.getContext().getAuthentication());
		
	}
	

}
