package com.ppublica.shopify.security.web;

import java.util.Arrays;
import java.util.HashSet;
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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class ShopifyHttpSessionOAuth2AuthorizationRequestRepositoryTests {

	OAuth2AuthorizationRequest authorizationRequest;
	
	ShopifyHttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository;
	
	@BeforeClass
	public static void testSetup() {
		Logger logger = Logger.getLogger(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class.getName());
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
		
		authorizationRequestRepository = new ShopifyHttpSessionOAuth2AuthorizationRequestRepository("/install");
	}
	
	@Test
	public void getAuthorizationRequestWhenNoneSavedThenReturnsNull() {
		
		MockHttpServletRequest request = new MockHttpServletRequest();
				
		Map<String, OAuth2AuthorizationRequest> authorizationRequests =
			this.authorizationRequestRepository.getAuthorizationRequests(request);

		Assert.assertEquals(0, authorizationRequests.size());
		
	}
	
	@Test
	public void getAuthorizationRequestShouldReturnAll() {
		
		MockHttpServletRequest request = new MockHttpServletRequest();
		
		
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);
				
		Map<String, OAuth2AuthorizationRequest> authorizationRequests =
				this.authorizationRequestRepository.getAuthorizationRequests(request);
		
		Assert.assertEquals(1, authorizationRequests.size());
		Assert.assertEquals(authorizationRequest, authorizationRequests.get("statekey"));
		
		
	}
	
	@Test
	public void saveAuthorizationRequestShouldSave() {
		
		MockHttpServletRequest request = new MockHttpServletRequest();

		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);

		Map<String, OAuth2AuthorizationRequest> authorizationRequests =
				this.authorizationRequestRepository.getAuthorizationRequests(request);
		
		Assert.assertEquals(1, authorizationRequests.size());
		Assert.assertEquals(authorizationRequest, authorizationRequests.get("statekey"));
		
	}
	
	
	@Test
	public void getAnAuthorizationRequestShouldReturnARequest() {
		
		MockHttpServletRequest request = new MockHttpServletRequest();

		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);
		
		OAuth2AuthorizationRequest otherAuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
										.clientId("other-client-id")
										.authorizationUri("https://testStore.myshopify.com/admin/oauth/authorize")
										.redirectUri("https://ppublica.com/login/app/oauth2/code/shopify")
										.scopes(new HashSet<>(Arrays.asList("read_products", "write_products")))
										.state("other-statekey")
										.build();

		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);
		this.authorizationRequestRepository.saveAuthorizationRequest(otherAuthorizationRequest, request);


		OAuth2AuthorizationRequest authorizationRequest =
				this.authorizationRequestRepository.getAnAuthorizationRequest(request);
		
		Assert.assertNotNull(authorizationRequest);
		
	}
	
	
	@Test
	public void extractRegistrationIdWhenExistingReturnsId() {
		
		MockHttpServletRequest request = new MockHttpServletRequest();
		
		request.setServletPath("/install/shopify");
		request.setScheme("https");
		request.setServerPort(443);
		request.setRequestURI("/install/shopify");
		request.setServerName("ppublica.com");
		
		String regId = this.authorizationRequestRepository.extractRegistrationId(request);
		
		Assert.assertEquals("shopify", regId);
		
	}
	
	@Test
	public void extractRegistrationIdWhenInvalidReturnsNull() {
		
		MockHttpServletRequest request = new MockHttpServletRequest();
		
		request.setServletPath("/install/");
		request.setScheme("https");
		request.setServerPort(443);
		request.setRequestURI("/install/");
		request.setServerName("ppublica.com");
		
		String regId = this.authorizationRequestRepository.extractRegistrationId(request);
		
		Assert.assertNull(regId);
		
	}	
	
}
