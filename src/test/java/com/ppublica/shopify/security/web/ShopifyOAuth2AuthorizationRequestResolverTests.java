package com.ppublica.shopify.security.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import com.ppublica.shopify.security.configurer.ShopifySecurityConfigurer;
import com.ppublica.shopify.security.service.TokenService;

import org.junit.Assert;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;

public class ShopifyOAuth2AuthorizationRequestResolverTests {
	ClientRegistrationRepository clientRegistrationRepository;
	ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository;
	String authorizationRequestBaseUri = "/install";
	String loginUri = "/init";
	
	@Before
	public void setup() {
		
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("shopify")
	            .clientId("client-id")
	            .clientSecret("client-secret")
	            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
	            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	            .redirectUriTemplate("{baseUrl}" + ShopifySecurityConfigurer.AUTHORIZATION_REDIRECT_PATH + "/{registrationId}")
	            .scope("read_products write_products")
	            .authorizationUri("https://{shop}/admin/oauth/authorize")
	            .tokenUri("https://{shop}/admin/oauth/access_token")
	            .clientName("Shopify")
	            .build();
		clientRegistrationRepository = new InMemoryClientRegistrationRepository(clientRegistration);
		customAuthorizationRequestRepository = mock(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.class);
		
	}
	
	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}
	
	@Test
	public void resolveWhenAlreadyAuthenticatedThenDoesNotResolve() {
		SecurityContext sc = new SecurityContextImpl();
		sc.setAuthentication(mock(OAuth2AuthenticationToken.class));
		SecurityContextHolder.setContext(sc);
		
		ShopifyOAuth2AuthorizationRequestResolver res = new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, authorizationRequestBaseUri, loginUri);
		
		Assert.assertNull(res.resolve(mock(HttpServletRequest.class)));
	}

	
	@Test
	public void resolveWhenNotAuthorizationRequestThenDoesNotResolve() {
		
		ShopifyOAuth2AuthorizationRequestResolver res = new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, authorizationRequestBaseUri, loginUri);
		HttpServletRequest req = mock(HttpServletRequest.class);
		when(req.getServletPath()).thenReturn("/other");
		
		Assert.assertNull(res.resolve(req));
		
	}
	
	
	@Test
	public void resolveWhenMissingIdAuthorizationRequestThenDoesNotResolve() {
		
		ShopifyOAuth2AuthorizationRequestResolver res = new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, authorizationRequestBaseUri, loginUri);
		HttpServletRequest req = mock(HttpServletRequest.class);
		when(req.getServletPath()).thenReturn("/install");
		
		Assert.assertNull(res.resolve(req));
		
	}
	
	@Test
	public void resolveWhenNoShopParamAuthorizationRequestThenRedirect() {
		
		ShopifyOAuth2AuthorizationRequestResolver res = new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, authorizationRequestBaseUri, loginUri);
		HttpServletRequest req = mock(HttpServletRequest.class);
		when(req.getServletPath()).thenReturn("/install/shopify");
		when(req.getScheme()).thenReturn("http");
		//doReturn("shop").when(req).getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		OAuth2AuthorizationRequest authReq = res.resolve(req);
		
		Assert.assertEquals(this.loginUri, authReq.getAuthorizationRequestUri());
		
	}
	
	
	@Test(expected = IllegalArgumentException.class)
	public void resolveWhenInvalidRegistrationParamAuthorizationRequestThenException() {
		
		ShopifyOAuth2AuthorizationRequestResolver res = new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, authorizationRequestBaseUri, loginUri);
		HttpServletRequest req = mock(HttpServletRequest.class);
		when(req.getServletPath()).thenReturn("/install/other");
		when(req.getScheme()).thenReturn("http");
		doReturn("shop").when(req).getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		res.resolve(req);
		
		
	}
	
	@Test
	public void resolveWhenValidAuthorizationRequestThenCorrectOAuth2AuthorizationRequestFound() {
		
		ShopifyOAuth2AuthorizationRequestResolver res = new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, authorizationRequestBaseUri, loginUri);
		HttpServletRequest req = mock(HttpServletRequest.class);
		when(req.getServletPath()).thenReturn("/install/shopify");
		when(req.getScheme()).thenReturn("https");
		when(req.getServerPort()).thenReturn(443);
		when(req.getRequestURI()).thenReturn("/install/shopify");
		when(req.getServerName()).thenReturn("ppublica.com");
		doReturn("testStore.myshopify.com").when(req).getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		ArgumentCaptor<OAuth2AuthorizationRequest> authReq = ArgumentCaptor.forClass(OAuth2AuthorizationRequest.class);
		ArgumentCaptor<HttpServletRequest> postReq = ArgumentCaptor.forClass(HttpServletRequest.class);
		
		res.resolve(req);
		
		verify(customAuthorizationRequestRepository).saveAuthorizationRequest(authReq.capture(), postReq.capture());
		
		OAuth2AuthorizationRequest foundReq = authReq.getValue();
		
		Assert.assertEquals("client-id", foundReq.getClientId());	
		Assert.assertTrue(foundReq.getAuthorizationRequestUri().contains("https://testStore.myshopify.com/admin/oauth/authorize?"));	
		Assert.assertTrue(foundReq.getAuthorizationRequestUri().contains("response_type="));		
		Assert.assertTrue(foundReq.getAuthorizationRequestUri().contains("client_id="));		
		Assert.assertTrue(foundReq.getAuthorizationRequestUri().contains("scope="));		
		Assert.assertTrue(foundReq.getAuthorizationRequestUri().contains("state="));		
		Assert.assertEquals("https://testStore.myshopify.com/admin/oauth/authorize", foundReq.getAuthorizationUri());		
		Assert.assertEquals("https://ppublica.com/login/app/oauth2/code/shopify", foundReq.getRedirectUri());
		
		Assert.assertEquals(2, foundReq.getAdditionalParameters().size());

		Assert.assertEquals("shopify", foundReq.getAdditionalParameters().get(OAuth2ParameterNames.REGISTRATION_ID));
		Assert.assertEquals("testStore.myshopify.com", foundReq.getAdditionalParameters().get(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN));
		
	}
	
	@Test
	public void resolveWhen2ArgsThenReturnNull() {
		
		ShopifyOAuth2AuthorizationRequestResolver res = new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, customAuthorizationRequestRepository, authorizationRequestBaseUri, loginUri);
		
		HttpServletRequest req = mock(HttpServletRequest.class);

		Assert.assertNull(res.resolve(req, "shopify"));
		
	}
	
	
	
}
