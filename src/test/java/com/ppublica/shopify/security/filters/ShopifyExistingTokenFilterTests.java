package com.ppublica.shopify.security.filters;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import com.ppublica.shopify.security.authentication.ShopifyOriginToken;

public class ShopifyExistingTokenFilterTests {
	
	ClientRegistration clientRegistration;
	OAuth2AuthorizedClientService clientService;
	String loginEndpoint;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyExistingTokenFilter.class.getName());
		logger.setLevel(Level.FINE);
		Handler handler = new ConsoleHandler();
		handler.setLevel(Level.FINE);
		logger.addHandler(handler);
	}
	
	@Before
	public void setup() {
		clientRegistration = ClientRegistration.withRegistrationId("shopify")
	            .clientId("client-id")
	            .clientSecret("client-secret")
	            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
	            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	            .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
	            .scope("read_products", "write_products")
	            .authorizationUri("https://{shop}/admin/oauth/authorize")
	            .tokenUri("https://{shop}/admin/oauth/access_token")
	            .clientName("Shopify")
	            .build();
		
		clientService = mock(OAuth2AuthorizedClientService.class);
		OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
		OAuth2AccessToken token = mock(OAuth2AccessToken.class);
		when(token.getTokenValue()).thenReturn("test-token");
		when(client.getAccessToken()).thenReturn(token);
		when(client.getClientRegistration()).thenReturn(clientRegistration);
		when(client.getPrincipalName()).thenReturn("test-store");
		doReturn(client).when(clientService).loadAuthorizedClient("shopify", "test-store");
		loginEndpoint = "/install/shopify";
	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();

	}

	// if request doesn't match path, continue with filter chain
	@Test
	public void doFilterWhenPathNoMatchThenContinue() throws Exception {
		ShopifyExistingTokenFilter filter = new ShopifyExistingTokenFilter(clientService, loginEndpoint);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install");
		request.setServletPath("/install");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		Authentication auth = mock(Authentication.class);
		
		SecurityContextHolder.getContext().setAuthentication(auth);
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		Assert.assertEquals(auth, SecurityContextHolder.getContext().getAuthentication());
	}
	
	// if Authentication is not ShopifyOriginToken, leave it, and continue
	@Test
	public void doFilterWhenAuthenticationNotShopifyOriginTokenThenLeaveItAndContinue() throws Exception {
		ShopifyExistingTokenFilter filter = new ShopifyExistingTokenFilter(clientService, loginEndpoint);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install/shopify");
		request.setServletPath("/install/shopify");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		Authentication auth = mock(Authentication.class);
		
		SecurityContextHolder.getContext().setAuthentication(auth);
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		Assert.assertEquals(auth, SecurityContextHolder.getContext().getAuthentication());
	}
	
	// if Authentication is ShopifyOriginToken, and if there's a shop param in req, and if store exists, set it as authentication, continue 
	@Test
	public void doFilterWhenAuthenticationCorrectTypeAndStoreExistsThenSetItAsAuthAndContinue() throws Exception {
		ShopifyExistingTokenFilter filter = new ShopifyExistingTokenFilter(clientService, loginEndpoint);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install/shopify");
		request.setServletPath("/install/shopify");
		request.addParameter("shop", "test-store");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		ShopifyOriginToken auth = mock(ShopifyOriginToken.class);
		
		SecurityContextHolder.getContext().setAuthentication(auth);
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		Authentication token = SecurityContextHolder.getContext().getAuthentication();
		
		Assert.assertTrue(token instanceof OAuth2AuthenticationToken);
	
	
	}
	
	// if Authentication is ShopifyOriginToken, and if there's a shop param in req, but store doesn't exist, clear authentication, continue
	@Test
	public void doFilterWhenAuthenticationCorrectTypeAndStoreDoesntExistThenClearAuthAndContinue() throws Exception {
		ShopifyExistingTokenFilter filter = new ShopifyExistingTokenFilter(clientService, loginEndpoint);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install/shopify");
		request.setServletPath("/install/shopify");
		request.addParameter("shop", "new-store");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		ShopifyOriginToken auth = mock(ShopifyOriginToken.class);
		
		SecurityContextHolder.getContext().setAuthentication(auth);
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		Authentication token = SecurityContextHolder.getContext().getAuthentication();
		
		Assert.assertNull(token);
	}
	
	// if Authentication is ShopifyOriginToken, and if there's no shop param in req, even if store exists, clear authentication, continue
	@Test
	public void doFilterWhenAuthenticationCorrectTypeAndNoShhopParamInRequestThenClearAndContinue() throws Exception {
		ShopifyExistingTokenFilter filter = new ShopifyExistingTokenFilter(clientService, loginEndpoint);
		
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/install/shopify");
		request.setServletPath("/install/shopify");

		MockHttpServletResponse response = new MockHttpServletResponse();
		
		ShopifyOriginToken auth = mock(ShopifyOriginToken.class);
		
		SecurityContextHolder.getContext().setAuthentication(auth);
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		
		Authentication token = SecurityContextHolder.getContext().getAuthentication();
		
		Assert.assertNull(token);
	
	}

	
	
	
}
